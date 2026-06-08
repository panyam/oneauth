// Command oneauth is a CLI front-end to the github.com/panyam/oneauth
// client SDK. The first shipped subcommand is `oneauth token`, which
// acquires OAuth 2.0 access tokens via browser / client_credentials /
// password / refresh_token grants against any RFC 8414 / OIDC AS.
//
// See: cmd/oneauth/SUMMARY.md for the full command map.
// See: https://github.com/panyam/oneauth/issues/255
package main

import (
	"fmt"
	"os"

	"github.com/panyam/oneauth/cmd/oneauth/cmd"
)

func main() {
	if err := cmd.NewRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
