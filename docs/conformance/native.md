# Go-native conformance report

Generated: 2026-11-19 23:27:31 UTC  
Package pattern: `./...`

## Summary

| Metric | Count |
|---|---|
| Tests run | 26 |
| Passing | 26 |
| Failing | 0 |
| Skipped (forbidden) | 0 |
| Known gaps in manifest | 28 |
| Gapped tests observed | 0 |
| Ratchet issues | 0 |

## Known gaps (sorted by expires, oldest first)

| Expires | Suite | Test | Issue | Owner | Status |
|---|---|---|---|---|---|
| 2027-12-31 | oidf | `fapi2-security-profile-final-test-plan/fapi2-security-profile-final-ensure-signed-client-assertion-with-RS256-fails` | 330 | panyam | expected-skip |
| 2027-12-31 | oidf | `fapi2-security-profile-final-test-plan/fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails` | 98 | panyam | expected-review |
| 2027-12-31 | oidf | `fapi2-security-profile-final-test-plan/fapi2-security-profile-final-happy-flow` | 339 | panyam | expected-warning |
| 2027-12-31 | oidf | `fapi2-security-profile-final-test-plan/fapi2-security-profile-final-par-attempt-reuse-request_uri` | 98 | panyam | expected-review |
| 2027-12-31 | oidf | `fapi2-security-profile-final-test-plan/fapi2-security-profile-final-par-attempt-to-use-expired-request_uri` | 98 | panyam | expected-review |
| 2027-12-31 | oidf | `fapi2-security-profile-final-test-plan/fapi2-security-profile-final-par-attempt-to-use-request_uri-for-different-client` | 98 | panyam | expected-review |
| 2027-12-31 | oidf | `fapi2-security-profile-final-test-plan/fapi2-security-profile-final-test-claims-parameter-identity-claims` | 339 | panyam | expected-warning |
| 2027-12-31 | oidf | `oidcc-basic-certification-test-plan,oidcc-dynamic-certification-test-plan,oidcc-test-plan-client_secret_post,oidcc-test-plan-client_secret_jwt,oidcc-test-plan-private_key_jwt/oidcc-ensure-request-object-with-redirect-uri` | 338 | panyam | expected-review |
| 2027-12-31 | oidf | `oidcc-basic-certification-test-plan,oidcc-dynamic-certification-test-plan,oidcc-test-plan-client_secret_post,oidcc-test-plan-client_secret_jwt,oidcc-test-plan-private_key_jwt/oidcc-server` | 339 | panyam | expected-warning |
| 2027-12-31 | oidf | `oidcc-basic-certification-test-plan,oidcc-test-plan-client_secret_post,oidcc-test-plan-client_secret_jwt,oidcc-test-plan-private_key_jwt/oidcc-ensure-registered-redirect-uri` | 477 | panyam | expected-review |
| 2027-12-31 | oidf | `oidcc-basic-certification-test-plan,oidcc-test-plan-client_secret_post,oidcc-test-plan-client_secret_jwt,oidcc-test-plan-private_key_jwt/oidcc-ensure-request-with-acr-values-succeeds` | 485 | panyam | expected-warning |
| 2027-12-31 | oidf | `oidcc-basic-certification-test-plan,oidcc-test-plan-client_secret_post,oidcc-test-plan-client_secret_jwt,oidcc-test-plan-private_key_jwt/oidcc-max-age-1` | 477 | panyam | expected-review |
| 2027-12-31 | oidf | `oidcc-basic-certification-test-plan,oidcc-test-plan-client_secret_post,oidcc-test-plan-client_secret_jwt,oidcc-test-plan-private_key_jwt/oidcc-prompt-login` | 477 | panyam | expected-review |
| 2027-12-31 | oidf | `oidcc-basic-certification-test-plan,oidcc-test-plan-client_secret_post,oidcc-test-plan-client_secret_jwt,oidcc-test-plan-private_key_jwt/oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` | 338 | panyam | expected-skip |
| 2027-12-31 | oidf | `oidcc-dynamic-certification-test-plan,oidcc-test-plan-client_secret_post,oidcc-test-plan-client_secret_jwt,oidcc-test-plan-private_key_jwt/oidcc-discovery-endpoint-verification` | 493 | panyam | expected-fail |
| 2027-12-31 | oidf | `oidcc-dynamic-certification-test-plan,oidcc-test-plan-client_secret_post,oidcc-test-plan-client_secret_jwt,oidcc-test-plan-private_key_jwt/oidcc-ensure-redirect-uri-in-authorization-request` | 493 | panyam | expected-review |
| 2027-12-31 | oidf | `oidcc-dynamic-certification-test-plan,oidcc-test-plan-client_secret_post,oidcc-test-plan-client_secret_jwt,oidcc-test-plan-private_key_jwt/oidcc-idtoken-unsigned` | 493 | panyam | expected-skip |
| 2027-12-31 | oidf | `oidcc-dynamic-certification-test-plan,oidcc-test-plan-client_secret_post,oidcc-test-plan-client_secret_jwt,oidcc-test-plan-private_key_jwt/oidcc-redirect-uri-query-added` | 493 | panyam | expected-review |
| 2027-12-31 | oidf | `oidcc-dynamic-certification-test-plan,oidcc-test-plan-client_secret_post,oidcc-test-plan-client_secret_jwt,oidcc-test-plan-private_key_jwt/oidcc-redirect-uri-query-mismatch` | 493 | panyam | expected-review |
| 2027-12-31 | oidf | `oidcc-dynamic-certification-test-plan,oidcc-test-plan-client_secret_post,oidcc-test-plan-client_secret_jwt,oidcc-test-plan-private_key_jwt/oidcc-registration-logo-uri` | 507 | panyam | expected-review |
| 2027-12-31 | oidf | `oidcc-dynamic-certification-test-plan,oidcc-test-plan-client_secret_post,oidcc-test-plan-client_secret_jwt,oidcc-test-plan-private_key_jwt/oidcc-registration-policy-uri` | 507 | panyam | expected-review |
| 2027-12-31 | oidf | `oidcc-dynamic-certification-test-plan,oidcc-test-plan-client_secret_post,oidcc-test-plan-client_secret_jwt,oidcc-test-plan-private_key_jwt/oidcc-registration-sector-bad` | 507 | panyam | expected-skip |
| 2027-12-31 | oidf | `oidcc-dynamic-certification-test-plan,oidcc-test-plan-client_secret_post,oidcc-test-plan-client_secret_jwt,oidcc-test-plan-private_key_jwt/oidcc-registration-sector-uri` | 507 | panyam | expected-skip |
| 2027-12-31 | oidf | `oidcc-dynamic-certification-test-plan,oidcc-test-plan-client_secret_post,oidcc-test-plan-client_secret_jwt,oidcc-test-plan-private_key_jwt/oidcc-registration-tos-uri` | 507 | panyam | expected-review |
| 2027-12-31 | oidf | `oidcc-dynamic-certification-test-plan,oidcc-test-plan-client_secret_post,oidcc-test-plan-client_secret_jwt,oidcc-test-plan-private_key_jwt/oidcc-request-uri-signed-rs256` | 338 | panyam | expected-fail |
| 2027-12-31 | oidf | `oidcc-dynamic-certification-test-plan,oidcc-test-plan-client_secret_post,oidcc-test-plan-client_secret_jwt,oidcc-test-plan-private_key_jwt/oidcc-request-uri-unsigned` | 338 | panyam | expected-fail |
| 2027-12-31 | oidf | `oidcc-dynamic-certification-test-plan,oidcc-test-plan-client_secret_post,oidcc-test-plan-client_secret_jwt,oidcc-test-plan-private_key_jwt/oidcc-server-rotate-keys` | 507 | panyam | expected-manual |
| 2027-12-31 | oidf | `oidcc-dynamic-certification-test-plan,oidcc-test-plan-client_secret_post,oidcc-test-plan-client_secret_jwt,oidcc-test-plan-private_key_jwt/oidcc-userinfo-rs256` | 485 | panyam | expected-fail |

