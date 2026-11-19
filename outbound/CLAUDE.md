# outbound — gotchas

Design and threat notes: [docs/OUTBOUND_CREDENTIALS.md](../docs/OUTBOUND_CREDENTIALS.md).

- **`githubtest` must behave like real GitHub.** When `make testgh` shows a difference, fix the fake and pin it with a unit test that fails against the old fake (PR #471 found three). Known behaviours: an unknown App ID is 404 "Integration not found" before the signature is checked; a refresh kills the previous access token; revoking a revoked token is 404, as are wrong client credentials.
- **`make testgh` needs your shell's env.** It reads `ONEAUTH_GH_APP_ID`, `_INSTALLATION_ID`, `_APP_KEY_FILE`, `_CLIENT_ID`, `_CLIENT_SECRET` (the `oneauthtest` App, installed on `panyam/oneauth-smoke-a` and `-b` only). A session started before they were exported doesn't see them; `source ~/.zshrc` first. The device-flow check (`ONEAUTH_GH_LIVE_DEVICE=1`) needs a person, so run it with `!`.
- **Handed-out tokens report `Expiry` early by `RefreshBefore`**, because `oauth2.NewClient` keeps a token until 10 seconds before `Expiry`. GitHub's own expiry is in `Extra("expires_at")`.
- **`GitHubRevoker` counts only 204 as revoked.** GitHub's 404 can't distinguish "already revoked" from a misconfigured revoker.
- **A `UserTokenStore` needs compare-and-swap on `Version`**, including "update of a missing record conflicts", or a refresh revives a disconnected token. `usertokentest.RunAll` checks both.
