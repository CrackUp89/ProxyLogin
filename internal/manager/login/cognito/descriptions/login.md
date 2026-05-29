Authenticates a user with a username and password.

**Request fields**:
- `user` *(required)* — username or email address.
- `password` *(required)* — user's password.
- `remember` *(optional)* — if `true`, issued cookies carry a persistent `Max-Age`/`Expires`; otherwise session cookies are issued (no expiry).

**Login steps**: a successful response does not always mean authentication is complete. When the response contains a `next_step` field the client must continue the login flow (e.g. MFA verification, password-change challenge) before tokens are issued.

**Token delivery — standard cookie mode** (`token.cookies.enabled: true`, `token.masquerade: false`):
When login completes with no further steps, tokens are delivered as HTTP cookies:
- `token.cookies.accessCookieName` (default `LATC`) — access token.
- `token.cookies.idCookieName` (default `LITC`) — ID token.
- `token.cookies.refreshCookieName` (default `LRTC`) — refresh token.
Cookie names are prefixed with `__Secure-` when `token.cookies.secure` is `true`.

**Token delivery — masquerade mode** (`token.masquerade: true`):
No access or ID token is returned directly. Instead, a single opaque masquerade token is issued via the `token.cookies.masqueradedCookieName` cookie (default `LMTC`, `__Secure-LMTC` when secure). Exchange it for real tokens by calling `/v1/unmask`.

**Token delivery — non-cookie mode** (`token.cookies.enabled: false`):
Tokens are returned directly in the response body.
