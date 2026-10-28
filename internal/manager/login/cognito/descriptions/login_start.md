Opens a login session. Every login flow starts here.

No authentication and no request body are needed.

**Response**:
- the login session id is set in an http-only cookie, `token.cookies.sessionCookieName` (default `LS`);
- `csrf_token` in the body — send it in the CSRF header (`http.csrf.headerName`, default `X-CSRF-Auth-Token`) with every following login-flow request.

Every following login-flow request (`/v1/login`, `/v1/login/external`, `/v1/login/mfa/*`, `/v1/login/password/update`) must send both the session cookie and the CSRF header. The session is bound to that CSRF token.

The session expires after the user pool client's auth session validity. Once login completes, the session is deleted and the cookie is cleared.

**Origin check**: when `http.csrf.allowedOrigins` is set, the request's `Origin` header must match one of the listed origins, otherwise `403` is returned. This applies to every login-flow endpoint.
