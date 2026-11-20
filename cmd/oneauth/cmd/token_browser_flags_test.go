package cmd

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --verify-id-token turns on BrowserLoginRequest.VerifyIDToken (issue 485).
func TestBrowserCommand_VerifyIDTokenFlag(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"--client-id", "c"}, false},
		{[]string{"--client-id", "c", "--verify-id-token"}, true},
	} {
		cmd := newBrowserCommand(&tokenFlags{})
		require.NoError(t, cmd.ParseFlags(tc.args))
		bf := &browserFlags{}
		bf.verifyID, _ = cmd.Flags().GetBool("verify-id-token")
		assert.Equal(t, tc.want, browserLoginRequest(bf, io.Discard).VerifyIDToken, "%v", tc.args)
	}
}
