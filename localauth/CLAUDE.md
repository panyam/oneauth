# localauth — gotchas

- **Signup with verification answers the same for a taken email**: `{"message": "Check your email to finish signing up."}`, no `user_id`.
- **A browser session's subject is the user ID.** `localauth` passes `user_id` to `HandleUser` (issue 339), and the reference server's session cookie uses it as `sub`. A custom `HandleUser` that builds a session reads `user_id` too.
