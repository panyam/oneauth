package authcodetest

import (
	"errors"
	"sync"
	"testing"

	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
)

// TestConcurrentConsumeOneWins races eight redemptions of one code. A
// backend whose check and mark aren't atomic lets two of them through, and
// both mint tokens from a single-use code. A backend that surfaces its own
// conflict error (a lost transaction) instead of ErrAuthorizationCodeUsed
// leaves the caller unable to tell a reuse from an outage.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2
// See: https://cwe.mitre.org/data/definitions/367.html
func TestConcurrentConsumeOneWins(t *testing.T, factory Factory) {
	s := factory(t).Store
	createCode(t, s, newCode())

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = consume(s, "code-abc")
		}()
	}
	wg.Wait()

	wins, used := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, core.ErrAuthorizationCodeUsed):
			used++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	assert.Equal(t, 1, wins, "exactly one redemption may succeed")
	assert.Equal(t, n-1, used, "every other redemption reports the code used")
}
