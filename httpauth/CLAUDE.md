# httpauth — gotchas

- **CSRF refuses cross-site posts.** `CSRFMiddleware` checks `Sec-Fetch-Site` and `Origin` on unsafe methods before the token; a test posting with `Origin` set to another host gets 403 even with a valid token. With `SessionID` set, a token minted before login stops validating after it.
