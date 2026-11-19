package partest

import (
	"context"
	"sync"
	"testing"

	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
)

// TestConcurrentConsumeOneWins races eight approvals of one pushed
// request. Exactly one may see Consumed true, or two approvals both issue
// a code for a single-use request_uri. None may fail with a backend
// conflict error.
//
// See: https://www.rfc-editor.org/rfc/rfc9126#section-4
// See: https://cwe.mitre.org/data/definitions/367.html
func TestConcurrentConsumeOneWins(t *testing.T, factory Factory) {
	s := factory(t).Store
	create(t, s, newRequest())

	const n = 8
	var wg sync.WaitGroup
	consumed := make([]bool, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := s.ConsumePushedAuthorizationRequest(context.Background(), &core.ConsumePushedAuthorizationRequestRequest{RequestURI: testRequestURI})
			errs[i] = err
			consumed[i] = err == nil && resp.Consumed
		}()
	}
	wg.Wait()

	wins := 0
	for i := range n {
		if errs[i] != nil {
			t.Errorf("unexpected error: %v", errs[i])
		}
		if consumed[i] {
			wins++
		}
	}
	assert.Equal(t, 1, wins, "exactly one approval may spend the request")
}
