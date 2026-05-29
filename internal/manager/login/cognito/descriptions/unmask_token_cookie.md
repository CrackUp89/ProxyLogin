Exchanges a masquerade token (read from cookie) for the real access, ID, and refresh tokens.

**This endpoint is intended for internal use only.** It should not be directly reachable by end users if the service owner wants to keep real tokens opaque. The typical use case is a reverse proxy (e.g. nginx) or a backend service that intercepts the user's request, calls this endpoint with the user's cookies forwarded, and appends the returned real tokens to the upstream request before passing it on — without ever exposing those tokens to the browser.

Returns `501 Not Implemented` when masquerade mode or cookie mode is disabled (`token.masquerade: false` or `token.cookies.enabled: false`).

Only fully operational when both masquerade mode and cookie mode are enabled (`token.masquerade: true`, `token.cookies.enabled: true`). The masquerade token is read automatically from the `token.cookies.masqueradedCookieName` cookie (default `LMTC`, `__Secure-LMTC` when secure).

**Query parameters**:
- `remember` *(optional, default `false`)* — if `true`, newly issued cookies carry a persistent `Max-Age`/`Expires`.

**On success**: real tokens are delivered as cookies (`token.cookies.accessCookieName`, `token.cookies.idCookieName`, `token.cookies.refreshCookieName`).
