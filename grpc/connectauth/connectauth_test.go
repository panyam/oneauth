package connectauth_test

// A Connect handler behind APIMiddleware with connectauth.OnAuthError refuses
// a call in the caller's own protocol: Connect, gRPC and gRPC-Web clients
// each read unauthenticated (no token, bad token) or permission_denied
// (missing scope) with their own library, and the RFC 6750 challenge is still
// in WWW-Authenticate. A plain HTTP request still gets the default 401 JSON.
//
// Without the adapter the codes already come out right, since every client
// maps HTTP 401 and 403 to unauthenticated and permission_denied. What gRPC
// and gRPC-Web clients lose is the reason and the challenge: they read
// "HTTP status 401 Unauthorized" with no WWW-Authenticate.
//
// See: https://www.rfc-editor.org/rfc/rfc6750#section-3.1
// See: https://connectrpc.com/docs/protocol/#error-codes
// See: https://github.com/panyam/oneauth/issues/463

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/grpc/connectauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	grpcmd "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	testSecret = "connectauth-test-secret-32-bytes!!"
	sayPath    = "/test.v1.EchoService/Say"
)

func mintToken(t *testing.T, scope string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":    "alice",
		"scopes": strings.Fields(scope),
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
	})
	s, err := tok.SignedString([]byte(testSecret))
	require.NoError(t, err)
	return s
}

// newServer serves Say over HTTP/2 + TLS behind a middleware requiring the
// "echo" scope.
func newServer(t *testing.T, withAdapter bool) *httptest.Server {
	t.Helper()
	mw := &apiauth.APIMiddleware{JWTSecretKey: testSecret}
	if withAdapter {
		mw.OnAuthError = connectauth.OnAuthError(mw)
	}
	say := connect.NewUnaryHandler(sayPath, func(ctx context.Context, req *connect.Request[wrapperspb.StringValue]) (*connect.Response[wrapperspb.StringValue], error) {
		return connect.NewResponse(wrapperspb.String("hi " + apiauth.GetSubjectFromAPIContext(ctx))), nil
	})
	mux := http.NewServeMux()
	mux.Handle(sayPath, mw.RequireScopes("echo")(say))
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

type callResult struct {
	code      string
	message   string
	challenge string
	reply     string
}

func callConnect(t *testing.T, srv *httptest.Server, token string, opts ...connect.ClientOption) callResult {
	t.Helper()
	client := connect.NewClient[wrapperspb.StringValue, wrapperspb.StringValue](srv.Client(), srv.URL+sayPath, opts...)
	req := connect.NewRequest(wrapperspb.String("x"))
	if token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	resp, err := client.CallUnary(context.Background(), req)
	if err == nil {
		return callResult{code: "ok", reply: resp.Msg.GetValue()}
	}
	var ce *connect.Error
	require.ErrorAs(t, err, &ce)
	return callResult{code: ce.Code().String(), message: ce.Message(), challenge: ce.Meta().Get("WWW-Authenticate")}
}

func callGRPCGo(t *testing.T, srv *httptest.Server, token string) callResult {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	conn, err := grpc.NewClient(strings.TrimPrefix(srv.URL, "https://"),
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(pool, "")))
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if token != "" {
		ctx = grpcmd.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	}
	var header grpcmd.MD
	out := &wrapperspb.StringValue{}
	err = conn.Invoke(ctx, sayPath, wrapperspb.String("x"), out, grpc.Header(&header))
	if err == nil {
		return callResult{code: "ok", reply: out.GetValue()}
	}
	st, ok := status.FromError(err)
	require.True(t, ok, "not a gRPC status: %v", err)
	challenge := ""
	if v := header.Get("www-authenticate"); len(v) > 0 {
		challenge = v[0]
	}
	return callResult{code: grpcCodeName(st.Code()), message: st.Message(), challenge: challenge}
}

// grpcCodeName spells a grpc-go code the way Connect does, so one table
// covers every client.
func grpcCodeName(c codes.Code) string {
	switch c {
	case codes.Unauthenticated:
		return "unauthenticated"
	case codes.PermissionDenied:
		return "permission_denied"
	default:
		return strings.ToLower(c.String())
	}
}

var clients = []struct {
	name string
	call func(*testing.T, *httptest.Server, string) callResult
}{
	{"connect", func(t *testing.T, s *httptest.Server, tok string) callResult { return callConnect(t, s, tok) }},
	{"connect-grpc", func(t *testing.T, s *httptest.Server, tok string) callResult {
		return callConnect(t, s, tok, connect.WithGRPC())
	}},
	{"connect-grpcweb", func(t *testing.T, s *httptest.Server, tok string) callResult {
		return callConnect(t, s, tok, connect.WithGRPCWeb())
	}},
	{"grpc-go", callGRPCGo},
}

func TestOnAuthError_RefusalInCallersProtocol(t *testing.T) {
	srv := newServer(t, true)
	good := mintToken(t, "echo")
	cases := []struct {
		name      string
		token     string
		code      string
		message   string
		challenge string
	}{
		{"no token", "", "unauthenticated", "missing authorization header", `Bearer realm="api"`},
		{"bad token", "not-a-jwt", "unauthenticated", "token is malformed", `error="invalid_token"`},
		{"missing scope", mintToken(t, "other"), "permission_denied", "requires scope echo", `error="insufficient_scope"`},
	}
	for _, cl := range clients {
		for _, tc := range cases {
			t.Run(cl.name+"/"+tc.name, func(t *testing.T) {
				got := cl.call(t, srv, tc.token)
				assert.Equal(t, tc.code, got.code)
				assert.Contains(t, got.message, tc.message)
				assert.Contains(t, got.challenge, tc.challenge)
				assert.True(t, strings.HasPrefix(got.challenge, `Bearer realm="api"`), "challenge = %q", got.challenge)
			})
		}
		t.Run(cl.name+"/good token", func(t *testing.T) {
			got := cl.call(t, srv, good)
			assert.Equal(t, "ok", got.code)
			assert.Equal(t, "hi alice", got.reply)
		})
	}
}

// Without the adapter, the gRPC-protocol clients get the right code from the
// HTTP status, but no challenge, and a message that opens with the HTTP
// status rather than the reason. This pins down what the adapter adds.
func TestOnAuthError_WithoutAdapterGRPCClientsLoseReason(t *testing.T) {
	srv := newServer(t, false)
	for _, cl := range clients[1:] {
		t.Run(cl.name, func(t *testing.T) {
			got := cl.call(t, srv, "not-a-jwt")
			assert.Equal(t, "unauthenticated", got.code)
			// grpc-go quotes the JSON body inside a transport error; the
			// Connect clients say only "HTTP status 401 Unauthorized".
			assert.False(t, strings.HasPrefix(got.message, "invalid token"), "message = %q", got.message)
			assert.Empty(t, got.challenge)
		})
	}
}

func TestOnAuthError_PlainHTTPKeepsDefaultResponse(t *testing.T) {
	srv := newServer(t, true)
	resp, err := srv.Client().Post(srv.URL+sayPath, "text/plain", strings.NewReader("x"))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Equal(t, `Bearer realm="api"`, resp.Header.Get("WWW-Authenticate"))
	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "unauthorized", body["error"])
}

func TestCode(t *testing.T) {
	assert.Equal(t, connect.CodePermissionDenied, connectauth.Code(&apiauth.AuthError{Code: "insufficient_scope"}))
	assert.Equal(t, connect.CodeUnauthenticated, connectauth.Code(&apiauth.AuthError{Code: "invalid_token"}))
	assert.Equal(t, connect.CodeUnauthenticated, connectauth.Code(assert.AnError))
}
