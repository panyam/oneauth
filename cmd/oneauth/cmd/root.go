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
		Long:          "OneAuth client CLI — currently ships `token`; sibling subcommands (introspect, dcr, jwks) are planned.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newTokenCommand())
	return root
}
