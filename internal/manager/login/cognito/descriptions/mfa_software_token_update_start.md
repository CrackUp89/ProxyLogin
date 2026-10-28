Starts a software token (TOTP) MFA update for the currently authenticated user.

Requires a valid auth token via cookie or `Authorization: Bearer` header.

No request body is needed. The server opens an update session bound to the user, sets it in an http-only cookie and returns a CSRF token.

**Response fields**:
- `csrf_token` — send it in the CSRF header with the following `/v1/mfa/software/update` and `/v1/mfa/update/software/verify` requests.

The update session expires after the user pool client's auth session validity and is closed once the new token is verified.
