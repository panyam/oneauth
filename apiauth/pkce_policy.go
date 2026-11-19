package apiauth

// PKCEPolicy says which clients must send a PKCE code_challenge on an
// authorization request (RFC 7636). Set it on OneAuthConfig.PKCEPolicy.
//
// OAuth 2.1 requires PKCE from every client, and so does oneauth by
// default. OpenID Connect Core and OAuth 2.0 make it optional for
// confidential clients, which authenticate at the token endpoint and so
// can't have a stolen code redeemed by someone else. An OIDC-certified
// provider has to accept them; the OIDF Basic OP plan sends PKCE in only
// one of its modules (mission 477).
//
// Per capability-gating umbrella #344.
type PKCEPolicy string

const (
	// PKCERequired refuses an authorization request without a
	// code_challenge, from any client. The zero value.
	PKCERequired PKCEPolicy = ""

	// PKCEOptionalForConfidential accepts an authorization request without
	// a code_challenge when the client is registered with a confidential
	// token_endpoint_auth_method. Public clients must still send one, and
	// so must every client when no AppStore says which kind it is. A code
	// issued without a challenge is redeemed only by an authenticated
	// client and only without a code_verifier, so a verifier can't be
	// injected afterwards (RFC 9700 §2.1.1).
	PKCEOptionalForConfidential PKCEPolicy = "optional_for_confidential"
)

// Valid reports whether p is one of the defined policies.
func (p PKCEPolicy) Valid() bool {
	return p == PKCERequired || p == PKCEOptionalForConfidential
}
