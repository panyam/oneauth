// Command provision configures the user's Authlete service for the
// tests/authlete interop suite by issuing the management-API mutations
// needed to flip every SKIP into a PASS. Idempotent.
//
// Usage:
//
//	AUTHLETE_API_SERVER=https://us.authlete.com \
//	AUTHLETE_SERVICEID=<numeric> \
//	AUTHLETE_ACCESS_TOKEN=<service token> \
//	  go run ./tests/authlete/cmd/provision/
//
// Invoked by `make authlete-provision`.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/panyam/oneauth/tests/authlete/provisioner"
)

func main() {
	apiServer := envOrDefault("AUTHLETE_API_SERVER", "https://api.authlete.com")
	serviceID := mustEnv("AUTHLETE_SERVICEID")
	accessToken := mustEnv("AUTHLETE_ACCESS_TOKEN")
	snapshotDir := envOrDefault("AUTHLETE_SNAPSHOT_DIR", "tests/authlete/.frontend")

	if testServiceID := os.Getenv("AUTHLETE_TEST_SERVICEID"); testServiceID != "" {
		log.Printf("AUTHLETE_TEST_SERVICEID set — targeting %s instead of %s", testServiceID, serviceID)
		serviceID = testServiceID
	}

	p := &provisioner.Provisioner{
		Client: provisioner.New(apiServer, serviceID, accessToken),
		Opts:   provisioner.Defaults(snapshotDir),
	}

	report, err := p.Provision(context.Background())
	if err != nil {
		log.Fatalf("provision failed: %v", err)
	}

	fmt.Printf("Status:                       %s\n", report.Status)
	fmt.Printf("JWKS generated on service:    %v\n", report.JWKSGenerated)
	if len(report.RARTypesAdded) > 0 {
		fmt.Printf("RAR types added (service):    %v\n", report.RARTypesAdded)
	}
	if len(report.ClientRARTypesAdded) > 0 {
		fmt.Printf("RAR types added (TestClient): %v\n", report.ClientRARTypesAdded)
	}
	fmt.Printf("Snapshot for deprovision:     %s\n", p.Opts.SnapshotPath)
	fmt.Println()
	fmt.Println("Introspection: tests use the java-oauth-server built-in resource")
	fmt.Println("server credentials (rs0/rs0-secret). Override via env if needed.")
}

func mustEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("required env var %s not set", name)
	}
	return v
}

func envOrDefault(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
