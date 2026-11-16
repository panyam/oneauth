// Package connectauth writes apiauth.APIMiddleware refusals in the protocol
// of the request: a Connect error for Connect, a grpc-status trailer for gRPC
// and gRPC-Web, and the middleware's default JSON for anything else.
//
// A gRPC or Connect client can't read an HTTP 401 page. It sees a transport
// failure, or a code like "unavailable", and can't tell a bad token from a
// network fault. Wire OnAuthError in front of a Connect handler instead:
//
//	mw := &apiauth.APIMiddleware{ /* ... */ }
//	mw.OnAuthError = connectauth.OnAuthError(mw)
//	mux.Handle(path, mw.ValidateToken(handler))
//
// See: https://connectrpc.com/docs/protocol/#error-codes
// See: https://github.com/grpc/grpc/blob/master/doc/statuscodes.md
// See: https://github.com/panyam/oneauth/issues/463
package connectauth

import (
	"errors"
	"net/http"

	"connectrpc.com/connect"
	"github.com/panyam/oneauth/apiauth"
)

// OnAuthError returns an APIMiddleware.OnAuthError for mw.
//
// For a Connect, gRPC or gRPC-Web request it sets the same WWW-Authenticate
// challenge (and DPoP-Nonce) the middleware would, then writes a Connect
// error. insufficient_scope becomes permission_denied, and every other
// refusal becomes unauthenticated. The error message is err.Error(), the
// same text the default JSON body carries in error_description. For any other request it writes the middleware's default
// response with mw.WriteAuthError, so REST clients on the same mux see no
// change.
func OnAuthError(mw *apiauth.APIMiddleware, opts ...connect.HandlerOption) func(http.ResponseWriter, *http.Request, error) {
	ew := connect.NewErrorWriter(opts...)
	return func(w http.ResponseWriter, r *http.Request, err error) {
		if !ew.IsSupported(r) {
			mw.WriteAuthError(w, r, err)
			return
		}
		mw.SetAuthErrorHeaders(w, err)
		_ = ew.Write(w, r, connect.NewError(Code(err), err))
	}
}

// Code is the Connect code for an APIMiddleware refusal: permission_denied
// for an *apiauth.AuthError with Code "insufficient_scope", unauthenticated
// otherwise. A refusal that isn't an *AuthError (a missing
// authorization_details type from RequireAuthorizationDetails) is
// unauthenticated, matching the middleware's own 401 for it.
func Code(err error) connect.Code {
	var ae *apiauth.AuthError
	if errors.As(err, &ae) && ae.Code == "insufficient_scope" {
		return connect.CodePermissionDenied
	}
	return connect.CodeUnauthenticated
}
