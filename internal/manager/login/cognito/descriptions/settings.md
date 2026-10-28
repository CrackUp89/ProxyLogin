Returns the service settings a client needs to talk to the API, so a client can adapt to how the service is configured instead of hard-coding it. No authentication required.

**Response fields**:
- `masquerade` — masquerade mode is on (`token.masquerade`): login issues an opaque masquerade token instead of real tokens.
- `cookies.enabled` — tokens are delivered as cookies (`token.cookies.enabled`); otherwise they come back in response bodies.
- `cookies.http_only` — token cookies are http-only (`token.cookies.httpOnly`), so JavaScript can't read them. Use `/v1/profile` to check the session.
- `cookies.access_cookie_name`, `cookies.id_cookie_name`, `cookies.refresh_cookie_name` — token cookie names, including the `__Secure-` prefix when it applies. Present in cookie mode without masquerade.
- `cookies.masquerade_cookie_name` — masquerade token cookie name. Present in cookie mode with masquerade.
- `csrf_header_name` — header that carries the CSRF token in login and update flows (`http.csrf.headerName`). Absent if the CSRF header check is disabled.
- `token_refresh_enabled` — `POST /v1/refresh` is available. False in masquerade mode.
- `password_reset_enabled` — the password reset endpoints are available (`password.reset.enabled`).
- `mfa.required` — users without MFA must set it up during login: either the user pool requires MFA, or the pool has it optional and `cognito.enforceMFA` is on.
