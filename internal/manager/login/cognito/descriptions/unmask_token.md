Exchanges a masquerade token (supplied in the request body) for the real access and ID tokens, plus the refresh token when `masquerade.unmaskRefreshToken` is enabled.

**This endpoint is intended for internal use only.** It should not be directly reachable by end users if the service owner wants to keep real tokens opaque. The typical use case is another backend service or a reverse proxy that holds the masquerade token and needs to exchange it for real tokens to forward to an upstream service — without ever exposing those tokens to the client.

Returns `501 Not Implemented` when masquerade mode is disabled (`token.masquerade: false`).

Available whenever masquerade mode is enabled (`token.masquerade: true`), with or without cookie mode.

**Request fields**:
- `token` *(required)* — masquerade token to exchange.
- `remember` *(optional, default `false`)* — if `true` and cookie mode is enabled, newly issued cookies carry a persistent `Max-Age`/`Expires`.

**On success**: real tokens are delivered as cookies (`token.cookies.accessCookieName`, `token.cookies.idCookieName`, `token.cookies.refreshCookieName`) when cookie mode is enabled, or returned directly in the response body otherwise.
