Sends a password reset link to the user's email address. No authentication required.

Returns `501 Not Implemented` when `password.reset.enabled` is `false`.

The email is sent only if an account with this address exists, but the response is the same either way, so it can't be used to discover accounts. The link points to `GET /v1/password/reset` on this service (built from `http.urlBase`). The token embedded in it is valid for `password.reset.tokenValidFor` minutes (default 60).

**Rate limit**: by default 1 request per 5 minutes per email address; configurable via `limits.rate.passwordResetRequest*`.

**Request fields**:
- `email` *(required)* — email address of the account to reset.
