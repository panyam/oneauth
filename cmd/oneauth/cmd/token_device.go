package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"time"

	"github.com/mdp/qrterminal/v3"
	"github.com/panyam/oneauth/client"
	"github.com/spf13/cobra"
)

// deviceFlags collects the flag set specific to the RFC 8628 device
// authorization grant subcommand.
type deviceFlags struct {
	clientID          string
	clientSecret      string
	clientSecretStdin bool
	scopes            string
	audience          string
	timeout           time.Duration
	openBrowser       bool
	showQR            bool
}

// newDeviceCommand builds `oneauth token device <issuer>`. The CLI
// drives the RFC 8628 polling loop on top of the SDK's
// AuthClient.DeviceAuthorization + PollDeviceToken primitives. Progress
// (user_code, verification URL, "waiting..." messages) goes to stderr so
// stdout stays a clean machine-parseable channel for the issued token.
func newDeviceCommand(tf *tokenFlags) *cobra.Command {
	df := &deviceFlags{}
	cmd := &cobra.Command{
		Use:   "device <issuer>",
		Short: "Acquire a token via the device authorization grant (RFC 8628)",
		Long: `Acquire an access token via the RFC 8628 device authorization grant —
the OAuth flow for devices with limited input (smart TVs, CLI tools, IoT).
Prints the verification URL and user_code to stderr, then polls the AS
until the user approves the authorization on another device, the code
is denied or expires, or --timeout elapses.

--open opens the verification URL in the user's default browser.
--qr renders an ASCII QR code of the verification URL to stderr — scan
it with a phone for the hand-off.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDevice(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], tf, df)
		},
	}
	cmd.Flags().StringVar(&df.clientID, "client-id", "", "OAuth client ID (required)")
	cmd.Flags().StringVar(&df.clientSecret, "client-secret", "", "OAuth client secret (omit for public clients)")
	cmd.Flags().BoolVar(&df.clientSecretStdin, "client-secret-stdin", false, "read client secret from stdin")
	cmd.Flags().StringVar(&df.scopes, "scopes", "", `space-delimited OAuth scopes (e.g., "read write")`)
	cmd.Flags().StringVar(&df.audience, "audience", "", "RFC 8707 audience indicator")
	cmd.Flags().DurationVar(&df.timeout, "timeout", 15*time.Minute, "how long to wait for the user to approve")
	cmd.Flags().BoolVar(&df.openBrowser, "open", false, "open the verification URL in the default browser")
	cmd.Flags().BoolVar(&df.showQR, "qr", false, "render the verification URL as an ASCII QR code to stderr")
	_ = cmd.MarkFlagRequired("client-id")
	return cmd
}

// devicePollSleep is the sleep primitive used by the polling loop.
// Replaced in tests with a no-op so tests don't spend 5s per poll.
var devicePollSleep = time.Sleep

// deviceOpenBrowser is the URL opener used when --open is set. Replaced
// in tests with a fake that records calls.
var deviceOpenBrowser = openURLInDefaultBrowser

// deviceWriteQR renders a URL as an ASCII QR code to w. Pinned as a var
// so tests can substitute a no-op.
var deviceWriteQR = func(w io.Writer, url string) {
	qrterminal.GenerateHalfBlock(url, qrterminal.L, w)
}

func runDevice(ctx context.Context, stdout, stderr io.Writer, issuer string, tf *tokenFlags, df *deviceFlags) error {
	secret, err := resolveSecret(df.clientSecret, df.clientSecretStdin, "--client-secret")
	if err != nil {
		return err
	}

	ac, meta, err := newAuthClient(issuer)
	if err != nil {
		return err
	}

	devResp, err := ac.DeviceAuthorization(ctx, &client.DeviceAuthorizationRequest{
		ClientID:     df.clientID,
		ClientSecret: secret,
		Scopes:       splitScopes(df.scopes),
		Audience:     df.audience,
	})
	if err != nil {
		return fmt.Errorf("device authorization: %w", err)
	}

	verifyURL := devResp.VerificationURI
	if devResp.VerificationURIComplete != "" {
		verifyURL = devResp.VerificationURIComplete
	}

	fmt.Fprintf(stderr, "To authorize, visit %s\n", devResp.VerificationURI)
	fmt.Fprintf(stderr, "and enter code: %s\n", devResp.UserCode)
	if devResp.VerificationURIComplete != "" {
		fmt.Fprintf(stderr, "(or open the convenience URL: %s)\n", devResp.VerificationURIComplete)
	}

	if df.showQR {
		deviceWriteQR(stderr, verifyURL)
	}
	if df.openBrowser {
		if openErr := deviceOpenBrowser(verifyURL); openErr != nil {
			// Non-fatal — the user can still type the code manually.
			fmt.Fprintf(stderr, "(could not open browser: %v)\n", openErr)
		} else {
			fmt.Fprintln(stderr, "Opening browser...")
		}
	}
	fmt.Fprintln(stderr, "Waiting for authorization...")

	interval := devResp.Interval
	if interval <= 0 {
		interval = 5
	}
	deadline := time.Now().Add(df.timeout)

	for {
		if !time.Now().Before(deadline) {
			return fmt.Errorf("device authorization: timed out after %s", df.timeout)
		}
		devicePollSleep(time.Duration(interval) * time.Second)
		if err := ctx.Err(); err != nil {
			return err
		}
		cred, pollErr := ac.PollDeviceToken(ctx, &client.PollDeviceTokenRequest{
			DeviceCode:   devResp.DeviceCode,
			ClientID:     df.clientID,
			ClientSecret: secret,
		})
		switch {
		case errors.Is(pollErr, client.ErrAuthorizationPending):
			continue
		case errors.Is(pollErr, client.ErrSlowDown):
			interval += 5
			fmt.Fprintf(stderr, "(server requested slow_down — polling every %ds)\n", interval)
			continue
		case errors.Is(pollErr, client.ErrAccessDenied):
			return fmt.Errorf("device authorization: user denied")
		case errors.Is(pollErr, client.ErrExpiredToken):
			return fmt.Errorf("device authorization: code expired before approval")
		case pollErr != nil:
			return fmt.Errorf("device authorization: %w", pollErr)
		}
		return emit(stdout, tf.format, cred, issuerFromMeta(meta, issuer), time.Now())
	}
}

// openURLInDefaultBrowser is the platform-specific browser launcher. The
// CLI keeps this local instead of pulling client.openBrowserDefault out
// of the SDK — sub-module isolation, and we only need the three-OS
// switch here.
func openURLInDefaultBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}
