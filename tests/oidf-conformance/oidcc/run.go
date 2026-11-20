package oidcc

import (
	"context"
	"fmt"
	"net/http"

	"github.com/panyam/oneauth/tests/oidf-conformance/oidfplan"
)

// Prepare signs up s.User and registers the plan's three clients with the
// server at serverURL: two using client_secret_basic and one using
// client_secret_post, filling in each client's ID and secret.
func Prepare(ctx context.Context, hc *http.Client, serverURL string, s *Setup) error {
	if err := oidfplan.SignUp(ctx, hc, serverURL, s.User); err != nil {
		return fmt.Errorf("sign up the browser user: %w", err)
	}
	redirect := RedirectURI(s.HarnessURL, s.Alias)
	register := func(method string) (Client, error) {
		id, secret, err := oidfplan.Register(ctx, hc, serverURL, RegistrationRequest(method, redirect, s.Scope))
		if err != nil {
			return Client{}, err
		}
		if secret == "" {
			return Client{}, fmt.Errorf("dcr issued no client_secret for a %s client", method)
		}
		return Client{ID: id, Secret: secret}, nil
	}
	for i := range s.Clients {
		c, err := register("client_secret_basic")
		if err != nil {
			return fmt.Errorf("register client %d: %w", i+1, err)
		}
		s.Clients[i] = c
	}
	c, err := register("client_secret_post")
	if err != nil {
		return fmt.Errorf("register the client_secret_post client: %w", err)
	}
	s.PostClient = c
	return nil
}

// Plan is the harness plan for s, ready for oidfplan.RunPlan.
func Plan(s Setup) oidfplan.Plan {
	return oidfplan.Plan{Name: PlanName, Variant: PlanVariant(), Config: PlanConfig(s)}
}

// FormPostPlan is the Form Post Basic OP plan for s. The harness asks for
// every response with response_mode=form_post, and oneauth answers with a
// page that posts it to the harness callback, which the same browser
// automation follows.
func FormPostPlan(s Setup) oidfplan.Plan {
	config := PlanConfig(s)
	config["description"] = "oneauth OIDC Form Post Basic OP exercise (issue 500)"
	return oidfplan.Plan{Name: FormPostPlanName, Variant: PlanVariant(), Config: config}
}
