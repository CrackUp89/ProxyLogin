Issues new access and ID tokens using a valid refresh token.

Returns `501 Not Implemented` when masquerade mode is enabled (`token.masquerade: true`). In masquerade mode there is no refresh token exposed to the client — token refresh is handled internally by the service.

**Token sources** (mutually exclusive):
- **Cookie mode** — the refresh token is read automatically from the `token.cookies.refreshCookieName` cookie (default `LRTC`, `__Secure-LRTC` when secure); `token` in the request body is ignored.
- **Non-cookie mode** — supply the refresh token explicitly in the `token` field.

**Request fields**:
- `user` *(optional)* — username or email address.
- `token` *(optional)* — refresh token; used only in non-cookie mode.
- `remember` *(optional)* — if `true`, newly issued cookies carry a persistent `Max-Age`/`Expires`; otherwise session cookies are issued.

**On success**: fresh access and ID tokens are delivered using the same mechanism as the `/v1/login` endpoint (cookies or response body, depending on configuration).
