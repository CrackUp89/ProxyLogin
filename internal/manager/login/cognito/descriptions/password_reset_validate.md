Validates the one-time token from a password reset email and redirects the user to the frontend reset page.

Returns `501 Not Implemented` when `password.reset.enabled` is `false`.

This is the intermediate step in the password reset flow. The link sent by `POST /v1/password/reset/request` points to this endpoint. It validates the token and, on success, issues a `302` redirect to `password.reset.redirectURL` (default `http://localhost/reset-password?token=%s`) with a session token embedded — which the frontend then passes to `POST /v1/password/reset/finalize`.

On failure, redirects to `password.reset.errorRedirectURL` if configured.

**Query parameters**:
- `token` *(required)* — the one-time reset token from the email link.
