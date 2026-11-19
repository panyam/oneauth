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
	var wg, ready sync.WaitGroup
	consumed := make([]bool, n)
	errs := make([]error, n)
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		ready.Add(1)
		go func() {
			defer wg.Done()
			// A read first so each goroutine holds a live pooled connection
			// and the consumes overlap.
			_, _ = s.GetPushedAuthorizationRequest(context.Background(), &core.GetPushedAuthorizationRequestRequest{RequestURI: testRequestURI})
			ready.Done()
			<-start
			resp, err := s.ConsumePushedAuthorizationRequest(context.Background(), &core.ConsumePushedAuthorizationRequestRequest{RequestURI: testRequestURI})
			errs[i] = err
			consumed[i] = err == nil && resp.Consumed
		}()
	}
	ready.Wait()
	close(start)
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
