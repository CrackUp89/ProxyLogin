Returns basic profile information decoded from the authenticated user's token.

This endpoint is particularly useful in masquerade mode, where real tokens are never exposed to the client and JavaScript cannot inspect them directly. It also serves as a general-purpose auth check: a `200` response confirms that a valid auth cookie (or `Authorization` header) is present, which is especially valuable when cookies are HTTP-only (`token.cookies.httpOnly: true`) — browsers block JavaScript from reading HTTP-only cookies, so this endpoint is the only way for client-side code to verify the session without a separate token.

**Token sources** (read by middleware, no request body needed):
- **Cookie mode** — auth token is read from `token.cookies.accessCookieName` (standard) or `token.cookies.masqueradedCookieName` (masquerade).
- **Non-cookie mode** — token is read from the `Authorization: Bearer <token>` header.

**Response fields**:
- `username` — the user's username.
- `email` — the user's email address.
- `email_verified` — whether the email address has been verified.
- `groups` — list of Cognito groups the user belongs to.
