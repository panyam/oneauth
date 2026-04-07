package client

import "net/url"

// TokenEndpointAuthMethod represents an OAuth 2.0 token endpoint
// authentication method as defined in RFC 6749 §2.3 and advertised by
// authorization servers via the "token_endpoint_auth_methods_supported"
// metadata field (RFC 8414 §2). The client uses SelectAuthMethod to
// negotiate which method to use based on what the AS supports.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3
// See: https://www.rfc-editor.org/rfc/rfc8414#section-2 (discovery metadata)
type TokenEndpointAuthMethod string

const (
	// AuthMethodNone indicates a public client with no client secret.
	// Only the client_id is sent as a form body parameter. This is the
	// correct method for native/SPA clients using PKCE without a secret.
	AuthMethodNone TokenEndpointAuthMethod = "none"

	// AuthMethodClientSecretPost sends client_id and client_secret as
	// form body parameters in the token request. Less secure than Basic
	// because credentials appear in the request body (potentially logged
	// by proxies or WAFs), but required by some AS implementations.
	AuthMethodClientSecretPost TokenEndpointAuthMethod = "client_secret_post"

	// AuthMethodClientSecretBasic sends client credentials via the HTTP
	// Basic authentication scheme (RFC 7617) in the Authorization header:
	// "Authorization: Basic base64(client_id:client_secret)". This is the
	// RFC 6749 §2.3.1 default and preferred method because credentials
	// stay out of the request body.
	AuthMethodClientSecretBasic TokenEndpointAuthMethod = "client_secret_basic"
)

// SelectAuthMethod chooses the appropriate token endpoint authentication
// method based on the client's credentials and the AS's advertised
// token_endpoint_auth_methods_supported metadata.
//
// Decision logic:
//  1. No client secret → "none" (public client, e.g., PKCE-only native apps)
//  2. AS advertises methods → pick best supported match, preferring
//     client_secret_basic over client_secret_post (credentials in header
//     are less likely to be logged than credentials in body)
//  3. AS doesn't advertise methods (nil/empty) → default to
//     client_secret_basic per RFC 6749 §2.3.1
//  4. AS advertises only unknown methods (e.g., private_key_jwt) →
//     fall back to client_secret_basic as a safe default
//
// This function is used by both LoginWithBrowser (auth code + PKCE flow)
// and ClientCredentialsToken (machine-to-machine flow) to negotiate
// how credentials are sent to the token endpoint.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13#section-3.2.1
// See: https://github.com/panyam/oneauth/issues/72
func SelectAuthMethod(clientSecret string, asMethods []string) TokenEndpointAuthMethod {
	if clientSecret == "" {
		return AuthMethodNone
	}
	if len(asMethods) == 0 {
		// RFC 6749 §2.3.1: default is HTTP Basic authentication scheme.
		return AuthMethodClientSecretBasic
	}
	// Prefer client_secret_basic (credentials not in body — more secure)
	for _, m := range asMethods {
		if m == string(AuthMethodClientSecretBasic) {
			return AuthMethodClientSecretBasic
		}
	}
	for _, m := range asMethods {
		if m == string(AuthMethodClientSecretPost) {
			return AuthMethodClientSecretPost
		}
	}
	// AS doesn't support any method we know — fall back to basic
	return AuthMethodClientSecretBasic
}

// applyAuthToForm configures form data (url.Values) with the appropriate
// client authentication parameters based on the selected method.
//
// For AuthMethodClientSecretBasic, this function intentionally does NOT add
// credentials to the form — callers must also call req.SetBasicAuth on the
// *http.Request to set the Authorization header. This two-step approach keeps
// form data clean and avoids accidentally sending credentials in both the
// header and the body.
//
// For AuthMethodClientSecretPost, both client_id and client_secret are added
// to the form body. For AuthMethodNone, only client_id is added.
func applyAuthToForm(method TokenEndpointAuthMethod, clientID, clientSecret string, data url.Values) {
	switch method {
	case AuthMethodClientSecretBasic:
		// Credentials go in Authorization header, not body.
		// client_id is still useful in body for some servers, but per RFC
		// it's not required when using Basic auth. We omit it to be clean.
	case AuthMethodClientSecretPost:
		data.Set("client_id", clientID)
		data.Set("client_secret", clientSecret)
	case AuthMethodNone:
		data.Set("client_id", clientID)
	default:
		// Unknown method — treat as none (client_id in body)
		data.Set("client_id", clientID)
	}
}
