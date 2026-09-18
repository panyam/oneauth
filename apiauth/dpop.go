package apiauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/utils"
)

// DPoP token type constants. TokenTypeDPoP is what the token endpoint
// reports in `token_type` for a sender-constrained token, and what a client
// must use in the `Authorization` header when presenting one.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-5
const (
	TokenTypeBearer = "Bearer"
	TokenTypeDPoP   = "DPoP"

	// DPoPHeader is the HTTP header carrying the proof JWT, on both the
	// token endpoint and (once the RS half lands) resource requests.
	DPoPHeader = "DPoP"

	// dpopProofTyp is the required `typ` header of a proof JWT. It exists
	// so a proof can never be confused with any other JWT the deployment
	// accepts — an access token or client assertion replayed as a proof
	// fails here before its signature is ever checked.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9449#section-4.2
	dpopProofTyp = "dpop+jwt"

	// dpopJTIPrefix namespaces DPoP proof jtis inside a JTIStore that is
	// shared with client-assertion (RFC 7523) and ID-JAG replay defense.
	// Without it, a client could burn an assertion's jti by sending a
	// proof carrying the same value.
	dpopJTIPrefix = "dpop:"
)

// defaultDPoPMaxAge is the accepted `iat` window in each direction. RFC 9449
// §11.1 wants it "reasonably brief"; 30s each way tolerates ordinary clock
// drift without giving a captured proof a useful replay lifetime. The `jti`
// check is what actually stops replay inside the window — this bounds how
// long the store must remember each jti.
const defaultDPoPMaxAge = 30 * time.Second

// defaultDPoPAlgs is the proof signing algorithms accepted by default.
// Asymmetric only: an HMAC "proof" would have to share its key with the AS,
// which is the opposite of proof of possession. `none` is impossible for the
// same reason.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-4.2
var defaultDPoPAlgs = []string{"ES256", "RS256", "PS256"}

// DPoPConfig configures a DPoPProofValidator.
type DPoPConfig struct {
	// AllowedAlgs restricts the proof `alg` header. Empty uses
	// defaultDPoPAlgs. Symmetric algorithms (HS*) and `none` are rejected
	// whatever this says.
	AllowedAlgs []string

	// MaxAge is how far the proof's `iat` may be from now, in either
	// direction. Zero uses defaultDPoPMaxAge. Future-dated proofs are
	// bounded by the same window so a client with a fast clock still
	// works and a client minting proofs hours ahead does not.
	MaxAge time.Duration

	// JTIStore backs replay detection. Nil wires an in-process store,
	// which is correct for single-node deployments only: with more than
	// one node behind a load balancer, a proof replayed against a
	// different node is not seen as a replay. Supply a shared store
	// (Redis SETNX, etc.) for a fleet.
	JTIStore JTIStore

	// EndpointURL is the externally-visible URL a proof's `htu` must
	// match, minus query and fragment. Leave empty to derive it from the
	// inbound request, which is correct only when the process terminates
	// TLS itself: behind a TLS-terminating proxy the derived scheme is
	// http while the client signs https, and every proof fails. Set this
	// to the URL clients actually call.
	//
	// This pins one exact URL, which suits a validator wired to a single
	// endpoint (the token endpoint). A resource server serving many paths
	// sets BaseURL instead.
	EndpointURL string

	// BaseURL is the externally-visible scheme and host of a resource
	// server, with no path. The expected `htu` is BaseURL joined to the
	// path of each inbound request, so one validator covers every route
	// the resource server exposes.
	//
	// Same proxy caveat as EndpointURL: set it whenever something in
	// front of the process terminates TLS or rewrites the Host header.
	// Empty derives both scheme and host per request.
	//
	// EndpointURL wins when both are set.
	BaseURL string

	// NonceSource issues and checks the server-provided nonces of
	// RFC 9449 §8 (authorization server) and §9 (resource server). Nil
	// disables the nonce protocol entirely, which is the default and
	// leaves proofs judged on `iat` and `jti` alone.
	NonceSource NonceSource

	// NoncePolicy decides which requests must carry a nonce. Nil never
	// demands one, so wiring a NonceSource without a policy changes
	// nothing: a proof is then accepted with or without a nonce.
	//
	// The RFC puts this decision out of scope on purpose (§8, "The logic
	// through which the server makes that determination is out of scope
	// of this document"), so it is a hook rather than a flag. Demanding
	// a nonce on every request costs every client an extra round trip on
	// first contact and breaks any client that has not implemented the
	// retry, so the useful policies are narrow: a high-value endpoint, a
	// client that has just failed something, a request from an unusual
	// address.
	NoncePolicy func(r *http.Request) bool

	// Now overrides the clock. Nil uses time.Now. Tests pin it to
	// validate the RFC's own example proofs against their fixed `iat`.
	Now func() time.Time
}

// DPoPProofValidator validates DPoP proof JWTs (RFC 9449 §4.3) and returns
// the RFC 7638 thumbprint of the key that signed them. The thumbprint is the
// value that goes into the issued token's `cnf.jkt`, which is what ties the
// token to this client's key.
//
// The validator is transport-agnostic in Validate and HTTP-aware in Confirm.
// Both are safe for concurrent use as long as the JTIStore is.
//
// See: https://www.rfc-editor.org/rfc/rfc9449
type DPoPProofValidator struct {
	allowedAlgs []string
	maxAge      time.Duration
	jtiStore    JTIStore
	endpointURL string
	baseURL     string
	nonceSource NonceSource
	noncePolicy func(r *http.Request) bool
	now         func() time.Time
}

// NewDPoPProofValidator builds a validator from cfg, filling defaults for
// the zero fields. Wire the result into OneAuthConfig.DPoP to opt the token
// endpoint into issuing sender-constrained tokens; leaving that slot nil
// keeps the AS bearer-only, per the capability-gating convention (#344).
func NewDPoPProofValidator(cfg DPoPConfig) *DPoPProofValidator {
	v := &DPoPProofValidator{
		allowedAlgs: cfg.AllowedAlgs,
		maxAge:      cfg.MaxAge,
		jtiStore:    cfg.JTIStore,
		endpointURL: cfg.EndpointURL,
		baseURL:     strings.TrimSuffix(cfg.BaseURL, "/"),
		nonceSource: cfg.NonceSource,
		noncePolicy: cfg.NoncePolicy,
		now:         cfg.Now,
	}
	if len(v.allowedAlgs) == 0 {
		v.allowedAlgs = defaultDPoPAlgs
	}
	if v.maxAge == 0 {
		v.maxAge = defaultDPoPMaxAge
	}
	if v.jtiStore == nil {
		v.jtiStore = NewInMemoryJTIStore()
	}
	if v.now == nil {
		v.now = time.Now
	}
	return v
}

// SigningAlgValuesSupported returns the accepted proof algorithms, for the
// `dpop_signing_alg_values_supported` AS metadata field (RFC 9449 §5.1).
// The returned slice is a copy; mutating it does not change the validator.
func (v *DPoPProofValidator) SigningAlgValuesSupported() []string {
	return append([]string(nil), v.allowedAlgs...)
}

// DPoPProofRequest is the input to DPoPProofValidator.Validate.
type DPoPProofRequest struct {
	// Proof is the raw compact JWT from the DPoP header.
	Proof string

	// Method is the HTTP method the proof must name in `htm`, compared
	// exactly (methods are case-sensitive per RFC 9110 §9.1).
	Method string

	// URL is the request URL the proof must name in `htu`. Query and
	// fragment are ignored on both sides, per RFC 9449 §4.3 item 9.
	URL string

	// AccessToken, when non-empty, requires the proof to carry a matching
	// `ath` (base64url SHA-256 of the token). Resource servers set this;
	// the token endpoint leaves it empty because no access token exists
	// yet at that point.
	AccessToken string

	// RequireNonce demands a valid server-issued `nonce` claim. Callers
	// that go through Confirm or ConfirmResource get this from the
	// configured NoncePolicy; a caller driving Validate directly decides
	// for itself.
	RequireNonce bool
}

// DPoPProofResponse is the output of DPoPProofValidator.Validate.
type DPoPProofResponse struct {
	// JKT is the RFC 7638 thumbprint of the proof's public key — the
	// value for `cnf.jkt` on issuance, and the value an RS compares an
	// access token's `cnf.jkt` against.
	JKT string

	// JWK is the public key the proof carried, parsed.
	JWK utils.JWK

	// Claims is the verified proof payload. Exposed so callers can read
	// extensions (`nonce`, and whatever a deployment adds) without
	// reparsing.
	Claims jwt.MapClaims
}

// Validate checks a DPoP proof JWT and returns its key thumbprint.
//
// Every failure returns a *GrantError with code `invalid_dpop_proof` and
// status 400, the error the token endpoint owes a client per RFC 9449 §5.
// Descriptions name the failed check, never the expected value, so a client
// probing for the server's clock or URL learns nothing from the response.
//
// Checks, in order (RFC 9449 §4.3):
//
//  1. `typ` is dpop+jwt and `alg` is an allowed asymmetric algorithm
//  2. the `jwk` header is a public key, with no private members
//  3. the signature verifies under that key
//  4. `jti`, `htm`, `htu` are present and match the request
//  5. `iat` is inside the acceptance window
//  6. `ath` matches, when the caller supplied an access token
//  7. `jti` has not been seen before
//
// Replay comes last on purpose: a malformed or badly signed proof must not
// consume a jti, or an attacker could poison the store with the jtis of
// proofs it expects an honest client to send.
func (v *DPoPProofValidator) Validate(ctx context.Context, req *DPoPProofRequest) (*DPoPProofResponse, error) {
	if req == nil || req.Proof == "" {
		return nil, invalidDPoPProof("DPoP proof is required")
	}

	var jwkHeader utils.JWK
	var proofKey any
	parsed, err := jwt.Parse(req.Proof, func(t *jwt.Token) (any, error) {
		if typ, _ := t.Header["typ"].(string); !strings.EqualFold(typ, dpopProofTyp) {
			return nil, fmt.Errorf("typ header must be %s", dpopProofTyp)
		}
		key, jwkVal, err := publicKeyFromProofHeader(t.Header["jwk"])
		if err != nil {
			return nil, err
		}
		jwkHeader, proofKey = jwkVal, key
		return key, nil
	},
		jwt.WithValidMethods(v.allowedAlgs),
		// The proof's own time claims are checked below against the
		// acceptance window; jwt/v5 would only check exp/nbf, and a
		// proof carries neither.
		jwt.WithoutClaimsValidation(),
	)
	if err != nil {
		return nil, invalidDPoPProof("proof JWT is not valid: " + err.Error())
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, invalidDPoPProof("proof JWT has no claims")
	}

	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, invalidDPoPProof("proof is missing jti")
	}
	if htm, _ := claims["htm"].(string); htm != req.Method {
		return nil, invalidDPoPProof("proof htm does not match the request method")
	}
	htu, _ := claims["htu"].(string)
	if !sameHTU(htu, req.URL) {
		return nil, invalidDPoPProof("proof htu does not match the request URI")
	}

	iat, err := claimSeconds(claims, "iat")
	if err != nil {
		return nil, invalidDPoPProof("proof is missing a usable iat")
	}
	if age := v.now().Sub(time.Unix(iat, 0)); age > v.maxAge || age < -v.maxAge {
		return nil, invalidDPoPProof("proof iat is outside the acceptance window")
	}

	if req.AccessToken != "" {
		ath, _ := claims["ath"].(string)
		if ath == "" || ath != accessTokenHash(req.AccessToken) {
			return nil, invalidDPoPProof("proof ath does not match the presented access token")
		}
	}

	// The nonce is checked before replay is recorded, so a client that
	// simply has not been told a nonce yet does not burn its `jti` on the
	// challenge round trip and can retry with the same proof body.
	if err := v.checkNonce(req.RequireNonce, claims); err != nil {
		return nil, err
	}

	// Remembered for the full window in both directions: a proof dated
	// maxAge in the future stays replayable until maxAge in the past, so
	// anything shorter would let it through twice.
	if v.jtiStore.SeenWithin(dpopJTIPrefix+jti, 2*v.maxAge) {
		return nil, invalidDPoPProof("proof jti has already been used")
	}

	jkt, err := utils.ComputeKid(proofKey, jwkHeader.Alg)
	if err != nil {
		return nil, invalidDPoPProof("proof jwk thumbprint could not be computed")
	}

	return &DPoPProofResponse{JKT: jkt, JWK: jwkHeader, Claims: claims}, nil
}

// checkNonce applies the §8 / §9 nonce rules.
//
// Three outcomes: not required, so anything passes; required and matching,
// which passes; required and absent, unknown or expired, which returns a
// NonceRequiredError carrying a fresh value for the client to retry with.
// The last case is a handshake step rather than a rejection, which is why it
// does not come back as invalid_dpop_proof.
func (v *DPoPProofValidator) checkNonce(required bool, claims jwt.MapClaims) error {
	if !required || v.nonceSource == nil {
		return nil
	}
	nonce, _ := claims["nonce"].(string)
	if nonce != "" && v.nonceSource.Valid(nonce) {
		return nil
	}

	issued, err := v.nonceSource.Issue()
	if err != nil {
		return invalidDPoPProof("a DPoP nonce is required but one could not be issued")
	}
	description := "a DPoP nonce is required"
	if nonce != "" {
		description = "the DPoP nonce is unknown or has expired"
	}
	return &NonceRequiredError{Nonce: issued, Description: description}
}

// nonceRequired reports whether this request must carry a nonce, per the
// configured policy. No source or no policy means never.
func (v *DPoPProofValidator) nonceRequired(r *http.Request) bool {
	return v.nonceSource != nil && v.noncePolicy != nil && v.noncePolicy(r)
}

// Confirm validates the DPoP proof on an inbound HTTP request and returns
// the confirmation to bind an issued token to.
//
// A request with no DPoP header returns (nil, nil): DPoP is opt-in per
// request, and a client that does not send a proof gets an ordinary bearer
// token. A request with more than one DPoP header is rejected rather than
// resolved, because picking one would let an attacker append a header to an
// honest client's request and choose which key the token binds to.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-4.3 (item 2)
func (v *DPoPProofValidator) Confirm(ctx context.Context, r *http.Request) (*core.Confirmation, error) {
	proofs := r.Header.Values(DPoPHeader)
	switch len(proofs) {
	case 0:
		return nil, nil
	case 1:
	default:
		return nil, invalidDPoPProof("request carries more than one DPoP header")
	}

	resp, err := v.Validate(ctx, &DPoPProofRequest{
		Proof:        proofs[0],
		Method:       r.Method,
		URL:          v.requestURL(r),
		RequireNonce: v.nonceRequired(r),
	})
	if err != nil {
		return nil, err
	}
	return &core.Confirmation{JKT: resp.JKT}, nil
}

// requestURL returns the URL a proof's `htu` is compared against: the pinned
// EndpointURL, else BaseURL joined to this request's path, else the inbound
// request's own scheme, host and path. The derived form deliberately ignores
// X-Forwarded-Proto — trusting it would let any client pick the scheme its
// proof is checked against, and the honest fix for a proxied deployment is
// to configure the URL.
func (v *DPoPProofValidator) requestURL(r *http.Request) string {
	if v.endpointURL != "" {
		return v.endpointURL
	}
	if v.baseURL != "" {
		return v.baseURL + r.URL.Path
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.Path
}

// ConfirmResource validates the DPoP proof on a request to a protected
// resource and returns the key it proves possession of. Unlike Confirm, a
// missing proof is an error: the caller only reaches here when the client
// presented its token under the DPoP scheme, so a proof was promised.
//
// accessToken is the token from the Authorization header. It is required,
// because RFC 9449 §7.1 has the resource server check `ath`, which is what
// stops a proof captured alongside one token from being reused with another
// token the same client holds.
//
// The returned confirmation is what the caller compares against the token's
// own `cnf` — this function proves possession of a key, and says nothing
// about whether that key is the one the token was issued to.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-7.1
func (v *DPoPProofValidator) ConfirmResource(ctx context.Context, r *http.Request, accessToken string) (*core.Confirmation, error) {
	proofs := r.Header.Values(DPoPHeader)
	switch len(proofs) {
	case 0:
		return nil, invalidDPoPProof("request presents a DPoP-bound token with no DPoP proof")
	case 1:
	default:
		return nil, invalidDPoPProof("request carries more than one DPoP header")
	}

	resp, err := v.Validate(ctx, &DPoPProofRequest{
		Proof:        proofs[0],
		Method:       r.Method,
		URL:          v.requestURL(r),
		AccessToken:  accessToken,
		RequireNonce: v.nonceRequired(r),
	})
	if err != nil {
		return nil, err
	}
	return &core.Confirmation{JKT: resp.JKT}, nil
}

// publicKeyFromProofHeader turns the proof's `jwk` header into a verification
// key. It rejects a JWK carrying any private or symmetric member: a proof
// that hands the server a private key is either a broken client leaking its
// own secret or an attacker trying to have the server verify with material it
// chose, and neither should mint a token.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-4.3 (item 5)
func publicKeyFromProofHeader(raw any) (any, utils.JWK, error) {
	if raw == nil {
		return nil, utils.JWK{}, fmt.Errorf("proof is missing the jwk header")
	}
	members, ok := raw.(map[string]any)
	if !ok {
		return nil, utils.JWK{}, fmt.Errorf("proof jwk header is not an object")
	}
	// "d" is the RSA/EC private exponent, "k" a symmetric key, and the
	// rest are RSA CRT parameters — any of them means this is not a
	// public key.
	for _, private := range []string{"d", "k", "p", "q", "dp", "dq", "qi"} {
		if _, found := members[private]; found {
			return nil, utils.JWK{}, fmt.Errorf("proof jwk header contains private key material")
		}
	}

	encoded, err := json.Marshal(members)
	if err != nil {
		return nil, utils.JWK{}, fmt.Errorf("proof jwk header is not encodable: %w", err)
	}
	var jwk utils.JWK
	if err := json.Unmarshal(encoded, &jwk); err != nil {
		return nil, utils.JWK{}, fmt.Errorf("proof jwk header is not a JWK: %w", err)
	}
	pub, _, err := utils.JWKToPublicKey(jwk)
	if err != nil {
		return nil, utils.JWK{}, fmt.Errorf("proof jwk header is not a usable public key: %w", err)
	}
	return pub, jwk, nil
}

// sameHTU compares a proof's `htu` against the request URL, ignoring query
// and fragment (RFC 9449 §4.3 item 9) and normalizing scheme and host case.
// The path is compared exactly: /token and /Token are different resources.
func sameHTU(htu, want string) bool {
	if htu == "" || want == "" {
		return false
	}
	got, err := url.Parse(htu)
	if err != nil {
		return false
	}
	expected, err := url.Parse(want)
	if err != nil {
		return false
	}
	return strings.EqualFold(got.Scheme, expected.Scheme) &&
		strings.EqualFold(got.Host, expected.Host) &&
		got.EscapedPath() == expected.EscapedPath()
}

// accessTokenHash computes the `ath` claim value: base64url, unpadded,
// SHA-256 of the access token as it appears in the Authorization header.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-4.2
func accessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// claimSeconds reads a numeric date claim. JSON numbers arrive as float64,
// but a claim written by a non-Go issuer can arrive as json.Number, so both
// are accepted.
func claimSeconds(claims jwt.MapClaims, name string) (int64, error) {
	switch v := claims[name].(type) {
	case float64:
		return int64(v), nil
	case json.Number:
		return v.Int64()
	default:
		return 0, fmt.Errorf("claim %q is not a number", name)
	}
}

// tokenTypeFor reports the `token_type` for a token with the given
// confirmation: DPoP when the token is sender-constrained, Bearer otherwise.
// Single source of truth so no grant can bind a token and then advertise it
// as a bearer token, which would have clients present it without a proof.
func tokenTypeFor(cnf *core.Confirmation) string {
	if cnf.IsEmpty() {
		return TokenTypeBearer
	}
	return TokenTypeDPoP
}

// invalidDPoPProof returns the RFC 9449 §5 error for a proof that failed
// validation. Distinct from invalid_request so a client can tell "your proof
// is wrong" from "your grant parameters are wrong" and retry the former with
// a fresh proof.
func invalidDPoPProof(description string) *GrantError {
	return &GrantError{Code: "invalid_dpop_proof", Description: description, Status: http.StatusBadRequest}
}
