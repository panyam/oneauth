package oidcc

import (
	"context"
	"fmt"
	"net/http"

	"github.com/panyam/oneauth/tests/oidf-conformance/oidfplan"
)

// ImplicitPlanName is the Implicit OP certification plan (issue 526). The
// plan picks the response type per module. It runs most of its 31 modules
// once with "id_token" and once with "id_token token", and the userinfo
// modules only with "id_token token". So one run covers both types, in 54
// module runs.
const ImplicitPlanName = "oidcc-implicit-certification-test-plan"

// FormPostImplicitPlanName is the Implicit OP plan with
// response_mode=form_post on every authorization request (issue 526).
const FormPostImplicitPlanName = "oidcc-formpost-implicit-certification-test-plan"

// ImplicitResponseTypes are the response types the implicit plans ask for.
// oneauth serves them with code_flow.implicit (issue 507), to clients
// registered for them.
var ImplicitResponseTypes = []string{"id_token", "id_token token"}

// ImplicitRegistrationRequest is the RFC 7591 body that registers the
// implicit plans' one client. RFC 7591 §2.1 pairs the implicit response
// types with the implicit grant, and oneauth's DCR refuses one without the
// other. The client stays confidential with client_secret_basic, which the
// plan's variant names, though no implicit flow reaches the token endpoint.
func ImplicitRegistrationRequest(redirectURI, scope string) map[string]any {
	return map[string]any{
		"client_name":                "oidf-oidcc-implicit",
		"redirect_uris":              []string{redirectURI},
		"grant_types":                []string{"implicit"},
		"response_types":             ImplicitResponseTypes,
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      scope,
	}
}

// PrepareImplicit signs up s.User and registers the implicit plans' client
// with the server at serverURL. The plans take one static client, so only
// s.Clients[0] gets filled in.
func PrepareImplicit(ctx context.Context, hc *http.Client, serverURL string, s *Setup) error {
	if err := oidfplan.SignUp(ctx, hc, serverURL, s.User); err != nil {
		return fmt.Errorf("sign up the browser user: %w", err)
	}
	id, secret, err := oidfplan.Register(ctx, hc, serverURL, ImplicitRegistrationRequest(RedirectURI(s.HarnessURL, s.Alias), s.Scope))
	if err != nil {
		return fmt.Errorf("register the implicit client: %w", err)
	}
	if secret == "" {
		return fmt.Errorf("dcr issued no client_secret for the implicit client")
	}
	s.Clients[0] = Client{ID: id, Secret: secret}
	return nil
}

// ImplicitPlan is the Implicit OP plan for s.
func ImplicitPlan(s Setup) oidfplan.Plan {
	return oidfplan.Plan{Name: ImplicitPlanName, Variant: PlanVariant(), Config: implicitPlanConfig(s, "oneauth OIDC Implicit OP exercise (issue 526)")}
}

// FormPostImplicitPlan is the Form Post Implicit OP plan for s. oneauth
// answers each implicit response with a page that posts the tokens to the
// harness callback as form fields, which the same browser automation
// follows.
func FormPostImplicitPlan(s Setup) oidfplan.Plan {
	return oidfplan.Plan{Name: FormPostImplicitPlanName, Variant: PlanVariant(), Config: implicitPlanConfig(s, "oneauth OIDC Form Post Implicit OP exercise (issue 526)")}
}

// implicitPlanConfig is PlanConfig with only the "client" the implicit
// plans' static_client variant asks for.
func implicitPlanConfig(s Setup, description string) map[string]any {
	config := PlanConfig(s)
	delete(config, "client2")
	delete(config, "client_secret_post")
	config["description"] = description
	return config
}
