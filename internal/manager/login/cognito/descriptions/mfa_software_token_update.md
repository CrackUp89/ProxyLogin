Begins the process of setting up or replacing the software token (TOTP) MFA method for an already authenticated user.

Requires a valid auth token via cookie or `Authorization: Bearer` header, plus the update session cookie and CSRF header from `/v1/mfa/software/update/start`.

No request body is needed. The server generates a new TOTP secret and returns it in the response. The update session moves on to the verify step, so this endpoint can be called only once per update session.

**Response fields**:
- `code` — TOTP secret to be entered into or scanned by the user's authenticator app.

After the user configures their authenticator app with this secret, the setup must be confirmed by calling `/v1/mfa/update/software/verify` with the first generated TOTP code.
