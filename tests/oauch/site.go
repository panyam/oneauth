// Package oauch drives an OAuch run against oneauth-server and checks its
// results against expected.yaml (issue 567). OAuch has no API, so the run
// goes through its dashboard: import a site, run the test set in a browser,
// resume the timed tests, and export the results as JSON.
package oauch

// Standards are the OAuch document IDs a run selects: RFC 6749, 6750, 6819,
// 7009, 7523 and 7636, the Security BCP (RFC 9700) and OIDC Core. They match
// the run docs/conformance/oauch.md describes.
var Standards = []string{"RFC6749", "RFC6750", "RFC6819", "RFC7009", "RFC7523", "RFC7636", "SecBCP", "OIDC"}

// Scope is the scope both clients ask for.
const Scope = "openid profile email offline_access"

// Discovery is the part of oneauth-server's discovery document a site needs.
type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
}

// Client is OAuch's ClientSettings.
type Client struct {
	ClientId     string
	ClientSecret string
	Scope        string
}

// Settings is the subset of OAuch's SiteSettings a run sets. The field
// names are OAuch's, since its importer reads them with Newtonsoft's
// defaults. Fields left out take OAuch's defaults.
type Settings struct {
	SelectedStandards []string
	AuthorizationUri  string
	TokenUri          string
	CallbackUri       string
	RevocationUri     string
	JwksUri           string
	TestUri           string
	OpenIdIssuer      string
	DefaultClient     Client
	AlternativeClient Client
	// TestMethod 1 is GET on TestUri, the userinfo endpoint.
	TestMethod int
	// PKCEDefault 2 is S256.
	PKCEDefault int
	// ResponseMode 100 lets OAuch detect the modes the server supports.
	ResponseMode int
	// ClientAuthenticationMechanism 0 is client_secret_basic.
	ClientAuthenticationMechanism int
}

// Site is OAuch's SiteData without test runs, the shape
// POST /Dashboard/Import takes as a one-element array.
type Site struct {
	Name                 string
	CurrentConfiguration Settings
}

// NewSite builds the site OAuch's "Add site" page would build from the
// discovery document, plus the callback, both clients and the standards.
func NewSite(name string, d Discovery, callback string, def, alt Client) Site {
	return Site{
		Name: name,
		CurrentConfiguration: Settings{
			SelectedStandards: Standards,
			AuthorizationUri:  d.AuthorizationEndpoint,
			TokenUri:          d.TokenEndpoint,
			CallbackUri:       callback,
			RevocationUri:     d.RevocationEndpoint,
			JwksUri:           d.JWKSURI,
			TestUri:           d.UserinfoEndpoint,
			OpenIdIssuer:      d.Issuer,
			DefaultClient:     def,
			AlternativeClient: alt,
			TestMethod:        1,
			PKCEDefault:       2,
			ResponseMode:      100,
		},
	}
}
