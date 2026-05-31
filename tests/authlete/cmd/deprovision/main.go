// Command deprovision restores the Authlete service to its
// pre-provision state using the snapshot written by `make
// authlete-provision`. Idempotent: if no snapshot exists (e.g.,
// because provision was never run, or deprovision already ran),
// reports that and exits 0.
//
// Invoked by `make authlete-deprovision`.
package main

import (
	"context"
	"errors"
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

	if err := p.Deprovision(context.Background()); err != nil {
		if errors.Is(err, provisioner.ErrSnapshotNotFound) {
			fmt.Printf("No snapshot at %s — nothing to deprovision.\n", p.Opts.SnapshotPath)
			return
		}
		log.Fatalf("deprovision failed: %v", err)
	}
	fmt.Println("Deprovisioned: service restored to pre-provision state.")
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
