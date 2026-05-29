Sets a new password using the session token obtained from the reset link and a verification code delivered to the user.

Returns `501 Not Implemented` when `password.reset.enabled` is `false`.

This is the final step of the password reset flow, called after the user has followed the reset link (which goes through `GET /v1/password/reset` and redirects to the frontend). No authentication required.

**Rate limit**: 5 requests per second per token.

**Request fields**:
- `token` *(required)* — session token received after the reset link was validated.
- `code` *(required)* — verification code delivered to the user (e.g. via email).
- `password` *(required)* — new password to set.
