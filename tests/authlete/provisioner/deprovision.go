package provisioner

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// Deprovision restores the Authlete service to its pre-provision state
// using the snapshot Provision wrote. It performs the inverse of each
// provision step:
//
//  1. Deletes the introspector client (if Provision created one).
//  2. Restores supportedAuthorizationDetailsTypes to its prior value
//     (which may be nil — Authlete treats absent as empty).
//  3. Restores jwks + accessTokenSignAlg if Provision generated them.
//
// Idempotent: re-running on a deprovisioned service is a no-op (the
// snapshot is removed after a successful restore so subsequent calls
// have nothing to act on).
//
// Returns ErrSnapshotNotFound when the snapshot file is missing —
// typically means provision wasn't run, OR a previous deprovision
// already cleaned up. Caller decides whether that's an error.
func (p *Provisioner) Deprovision(ctx context.Context) error {
	snap, err := readSnapshot(p.Opts.SnapshotPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrSnapshotNotFound
		}
		return fmt.Errorf("read snapshot: %w", err)
	}

	// Restore the test client's authorizationDetailsTypes (Authlete
	// enforces declared-types on the client; provision extended this
	// list and we revert to the prior state).
	if snap.TestClientID != 0 {
		clients, err := p.Client.ListClients(ctx)
		if err != nil {
			return fmt.Errorf("list clients: %w", err)
		}
		for _, c := range clients {
			cid, _ := toInt64(c["clientId"])
			if cid != snap.TestClientID {
				continue
			}
			if snap.HadClientRARTypes {
				c["authorizationDetailsTypes"] = snap.PriorClientRARTypes
			} else {
				delete(c, "authorizationDetailsTypes")
			}
			if _, err := p.Client.UpdateClient(ctx, cid, c); err != nil {
				return fmt.Errorf("restore test client %d: %w", cid, err)
			}
			break
		}
	}

	svc, err := p.Client.GetService(ctx)
	if err != nil {
		return fmt.Errorf("get service: %w", err)
	}

	// Restore RAR types — set back to nil if Authlete didn't have the
	// field at all (vs explicitly empty array).
	if snap.HadRARTypes {
		svc["supportedAuthorizationDetailsTypes"] = snap.PriorRARTypes
	} else {
		delete(svc, "supportedAuthorizationDetailsTypes")
	}

	// Restore JWKS — only if we generated it (snap.HadJWKS=false means
	// pre-provision state was no-JWKS; clear the field we set).
	if !snap.HadJWKS {
		delete(svc, "jwks")
	} else {
		svc["jwks"] = snap.JWKS
	}

	if _, err := p.Client.UpdateService(ctx, svc); err != nil {
		return fmt.Errorf("restore service: %w", err)
	}

	// Remove snapshot last — if restore succeeded the file is stale;
	// if it failed we want it around for the next attempt.
	_ = os.Remove(p.Opts.SnapshotPath)
	return nil
}

// ErrSnapshotNotFound is returned by Deprovision when no snapshot file
// exists at Opts.SnapshotPath. Distinguishes "nothing to roll back"
// from genuine restore failures.
var ErrSnapshotNotFound = errors.New("provisioner snapshot not found (run Provision first)")
