package fapi2

import (
	"context"
	"fmt"
	"net/http"

	"github.com/panyam/oneauth/tests/oidf-conformance/oidfplan"
)

// Prepare signs up s.User and registers both of s.Clients with the server
// at serverURL, filling in each client's ID and key.
func Prepare(ctx context.Context, hc *http.Client, serverURL string, s *Setup) error {
	if err := oidfplan.SignUp(ctx, hc, serverURL, s.User); err != nil {
		return fmt.Errorf("sign up the browser user: %w", err)
	}
	for i := range s.Clients {
		key, err := NewClientKey()
		if err != nil {
			return err
		}
		id, _, err := oidfplan.Register(ctx, hc, serverURL, RegistrationRequest(key, ClientRedirectURI(s.HarnessURL, s.Alias, i), s.Scope))
		if err != nil {
			return fmt.Errorf("register client %d: %w", i+1, err)
		}
		s.Clients[i] = RegisteredClient{ID: id, Key: key}
	}
	return nil
}

// Plan is the harness plan for s, ready for oidfplan.RunPlan.
func Plan(s Setup) oidfplan.Plan {
	return oidfplan.Plan{Name: PlanName, Variant: PlanVariant(), Config: PlanConfig(s)}
}
