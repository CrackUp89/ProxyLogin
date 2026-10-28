Validates the one-time token from a password reset email and redirects the user to the frontend reset page.

Returns `501 Not Implemented` when `password.reset.enabled` is `false`.

This is the intermediate step in the password reset flow. The link sent by `POST /v1/password/reset/request` points to this endpoint. It validates the token and, on success, issues a `302` redirect to `password.reset.redirectURL` (default `http://localhost/reset-password?token=%[1]s`) with a new session token in place of `%[1]s`. The frontend then passes it to `POST /v1/password/reset/finalize`. The session token is valid for `password.reset.tokenValidFor` minutes.

On failure, redirects to `password.reset.errorRedirectURL` if configured; otherwise an error is returned.

**Query parameters**:
- `token` *(required)* — the one-time reset token from the email link.
