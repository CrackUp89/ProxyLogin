Authenticates a user with a username and password.

Requires the login session cookie and CSRF header from `/v1/login/start`.

**Request fields**:
- `user` *(required)* — username or email address.
- `password` *(required)* — user's password.
- `remember` *(optional)* — if `true`, issued cookies carry a persistent `Max-Age`/`Expires`; otherwise session cookies are issued (no expiry).

**Login steps**: a successful response does not always mean authentication is complete. The response body contains either `next_step` or `auth_result`:
- `next_step` — the client must continue the login flow (e.g. MFA verification, password-change challenge) before tokens are issued. `next_step.step` names the step and `next_step.payload` carries step-specific data. The login session is rotated: the response sets a new session cookie, which must be used for the next step. The CSRF token stays the same.
- `auth_result` — login is complete. The login session is deleted and its cookie is cleared.

**Token delivery — standard cookie mode** (`token.cookies.enabled: true`, `token.masquerade: false`):
When login completes with no further steps, tokens are delivered as HTTP cookies:
- `token.cookies.accessCookieName` (default `LATC`) — access token.
- `token.cookies.idCookieName` (default `LITC`) — ID token.
- `token.cookies.refreshCookieName` (default `LRTC`) — refresh token.
Cookie names are prefixed with `__Secure-` when `token.cookies.secure` is `true`.

**Token delivery — masquerade mode** (`token.masquerade: true`):
No access or ID token is returned directly. Instead, a single opaque masquerade token is issued via the `token.cookies.masqueradedCookieName` cookie (default `LMTC`, `__Secure-LMTC` when secure), or in the response body when cookies are disabled. Exchange it for real tokens by calling `/v1/unmask`.

**Token delivery — non-cookie mode** (`token.cookies.enabled: false`):
Tokens are returned directly in the response body.
