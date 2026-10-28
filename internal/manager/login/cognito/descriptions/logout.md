Revokes the user's token and clears auth cookies.

**Token sources** (in order of precedence):
- **Request body** — if `token` is provided it is used directly. In masquerade mode this must be the masquerade token, otherwise the refresh token.
- **Cookie mode** — when no token is supplied in the body, the token is extracted from cookies. Which cookie is read depends on the active mode:
  - Standard mode: `token.cookies.refreshCookieName` (default `LRTC`, `__Secure-LRTC` when secure).
  - Masquerade mode: `token.cookies.masqueradedCookieName` (default `LMTC`, `__Secure-LMTC` when secure).

**Request fields**:
- `token` *(optional)* — token to revoke; if omitted the token is read from cookies as described above.

**On success**: all auth cookies (`LATC`, `LITC`, `LRTC`, `LMTC`) and the login session cookie (`LS`) are cleared. The refresh token is revoked in Cognito in the background, and in masquerade mode the masquerade token is deleted. The response is always successful once a token is supplied, even if revocation later fails.
