Sends a password reset link to the user's email address. No authentication required.

Returns `501 Not Implemented` when `password.reset.enabled` is `false`.

The reset email contains a link whose format is configured via `password.reset.redirectURL` (default `http://localhost/reset-password?token=%s`). The token embedded in the link is valid for the duration set by `password.reset.tokenValidFor` (default 60 minutes). Clicking the link calls `GET /v1/password/reset`, which validates the token and redirects to the frontend reset page.

**Rate limit**: 1 request per 5 minutes per email address.

**Request fields**:
- `email` *(required)* — email address of the account to reset.
