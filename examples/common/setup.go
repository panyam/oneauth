// Package common holds helpers shared across oneauth examples — the seam
// where "every example needs this now" updates land in one place instead
// of N copy-paste edits.
//
// Each example follows the same shape:
//
//	main.go         — boots the auth server and resource server. With
//	                  --serve, binds them on real ports and blocks so any
//	                  external client can drive them. Default behavior
//	                  spins them up in-process and runs the walkthrough.
//	walkthrough.go  — defines the demokit demo (the "client") that drives
//	                  the servers and prints the protocol exchange.
//
// SetupRenderer wires the TUI renderer when --tui is passed; the default
// PlainRenderer stays in place otherwise. Examples should call this
// before demo.Execute().
package common

import (
	"log"

	"github.com/panyam/demokit"
	"github.com/panyam/demokit/tui"
)

// SetupRenderer enables the TUI renderer when the user passes --tui.
// No-op otherwise so the default plain renderer keeps working in CI and
// piped environments.
func SetupRenderer(demo *demokit.Demo) {
	if demokit.IsTUI() {
		demo.WithRenderer(tui.New())
	}
}

// NewOneAuthLogger returns the canonical demokit ColorLogger used across
// oneauth examples. The baseline rules tint:
//
//   - error= and ERROR markers (red)
//   - [http] → outbound HTTP requests (gray / dim blue)
//   - [http] ← inbound HTTP responses (cyan / blue)
//   - "minted" / "issued" token-mint events (bright green / green)
//
// extraRules append to the baseline so callers can tint
// example-specific lines without losing the shared set.
func NewOneAuthLogger(prefix string, extraRules ...demokit.ColorRule) *log.Logger {
	rules := []demokit.ColorRule{
		{Contains: "error=", DarkColor: demokit.ANSIRed},
		{Contains: "ERROR", DarkColor: demokit.ANSIRed},
		{Contains: "[http] →", DarkColor: demokit.ANSIGray, LightColor: demokit.ANSIDimBlue},
		{Contains: "[http] ←", DarkColor: demokit.ANSICyan, LightColor: demokit.ANSIBlue},
		{Contains: "minted", DarkColor: demokit.ANSIBrightGreen, LightColor: demokit.ANSIGreen},
		{Contains: "issued", DarkColor: demokit.ANSIBrightGreen, LightColor: demokit.ANSIGreen},
	}
	rules = append(rules, extraRules...)
	return demokit.NewColorLogger(prefix, rules)
}
