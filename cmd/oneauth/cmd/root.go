package cmd

import (
	"github.com/spf13/cobra"
)

// NewRoot builds the `oneauth` Cobra command tree. Exposed as a
// constructor (rather than a package-level var) so tests can build a
// fresh tree per case — Cobra commands carry parse state on their flag
// set, which leaks across reuse.
func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "oneauth",
		Short:         "OneAuth client CLI",
		Long:          "OneAuth client CLI for OAuth 2.0 token acquisition, introspection, dynamic client registration, and JWKS inspection.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newTokenCommand())
	root.AddCommand(newIntrospectCommand())
	root.AddCommand(newDCRCommand())
	root.AddCommand(newJWKSCommand())
	return root
}
