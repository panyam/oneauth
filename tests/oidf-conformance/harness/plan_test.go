package harness

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A plan with variants (FAPI 2.0's client_auth_type, sender_constrain, ...)
// takes them as a JSON `variant` query parameter on plan creation, next to
// the plan name; the body stays the configuration.
func TestCreatePlanWithVariant_SendsVariantAndConfig(t *testing.T) {
	var gotVariant, gotPlan string
	var gotBody map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/api/plan", func(w http.ResponseWriter, r *http.Request) {
		gotPlan = r.URL.Query().Get("planName")
		gotVariant = r.URL.Query().Get("variant")
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "plan-9"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTPClient: srv.Client()}

	id, err := c.CreatePlanWithVariant(context.Background(), "fapi2-security-profile-final-test-plan",
		map[string]string{"sender_constrain": "dpop"}, map[string]any{"alias": "a"})
	require.NoError(t, err)
	assert.Equal(t, "plan-9", id)
	assert.Equal(t, "fapi2-security-profile-final-test-plan", gotPlan)
	assert.JSONEq(t, `{"sender_constrain":"dpop"}`, gotVariant)
	assert.Equal(t, "a", gotBody["alias"])
}

// GetPlan lists the modules the harness chose for the plan's variants, each
// with the module-level variant RunTest has to pass back.
func TestGetPlan_ListsModulesWithTheirVariants(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/plan/plan-9", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"_id":"plan-9","planName":"p","modules":[
			{"testModule":"fapi2-security-profile-final-happy-flow","variant":{"fapi_request_method":"unsigned"},"instances":[]},
			{"testModule":"fapi2-security-profile-final-refresh-token","variant":{},"instances":["t1"]}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTPClient: srv.Client()}

	plan, err := c.GetPlan(context.Background(), "plan-9")
	require.NoError(t, err)
	require.Len(t, plan.Modules, 2)
	assert.Equal(t, "fapi2-security-profile-final-happy-flow", plan.Modules[0].TestModule)
	assert.Equal(t, map[string]string{"fapi_request_method": "unsigned"}, plan.Modules[0].Variant)
	assert.Equal(t, []string{"t1"}, plan.Modules[1].Instances)
}
