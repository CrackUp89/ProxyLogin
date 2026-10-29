ProxyLogin is an authentication proxy built on top of AWS Cognito. It handles the full login lifecycle — credential verification, multi-factor authentication, password management, and token delivery — and exposes it as a single HTTP API intended to sit in front of your application or reverse proxy.

---

## Token delivery modes

All token-issuing endpoints share the same delivery behaviour, controlled by two configuration flags:

**Standard cookie mode** (`token.cookies.enabled: true`, `token.masquerade: false`):
On successful authentication, three cookies are set:
- `token.cookies.accessCookieName` (default `LATC`) — access token.
- `token.cookies.idCookieName` (default `LITC`) — ID token.
- `token.cookies.refreshCookieName` (default `LRTC`) — refresh token.

**Masquerade mode** (`token.masquerade: true`):
Real tokens are never exposed to the client. Instead a single opaque masquerade token is issued via the `token.cookies.masqueradedCookieName` cookie (default `LMTC`), or in the response body when cookies are disabled. It can be exchanged for real tokens by a trusted backend service or reverse proxy via `GET /v1/unmask` (cookie source) or `POST /v1/unmask` (body source) — see [Masquerade mode](#masquerade-mode) below.

**Non-cookie mode** (`token.cookies.enabled: false`):
All tokens are returned directly in the response body.

Cookie names are prefixed with `__Secure-` when `token.cookies.secure` is `true`.

---

## Login flow

Login is a multi-step process that always starts with `POST /v1/login/start`. It returns a `csrf_token` and sets the login session cookie (`token.cookies.sessionCookieName`, default `LS`, always http-only).

Every following login request must send:
- the login session cookie;
- the CSRF token in the `http.csrf.headerName` header (default `X-CSRF-Auth-Token`).

Each response either completes authentication (tokens are delivered and the session cookie is cleared) or returns a `next_step` object indicating what the client must do next. A step response may set a new session cookie, so always keep the latest one. The CSRF token stays the same for the whole flow.

```
POST /v1/login/start
      │
      ▼
POST /v1/login
      │
      ├─ next_step: new_password ──────────────────► POST /v1/login/password/update
      │                                                      │
      ├─ next_step: mfa_setup ─────────────────────► POST /v1/login/mfa/setup
      │       │                                              │
      │       └─ next_step: mfa_token_setup_verify           │
      │                    └──────────────────────► POST /v1/login/mfa/setup/verify
      │                                                      │
      ├─ next_step: mfa_select ────────────────────► POST /v1/login/mfa/select
      │                                                      │
      ├─ next_step: mfa_software_token_verify ◄─────────────┤
      ├─ next_step: mfa_sms_verify            ◄─────────────┤
      └─ next_step: mfa_email_verify          ◄─────────────┘
                    └──────────────────────────────► POST /v1/login/mfa/verify
                                                              │
                                                         [tokens issued]
```

### Step details

**`POST /v1/login/start`** — Opens a login session. Returns `csrf_token` and sets the session cookie.

**`POST /v1/login`** — Submit username and password. Accepts an optional `remember` flag that controls cookie expiry.

**`POST /v1/login/password/update`** — Required when Cognito returns a `new_password` challenge (administratively set or expired password). Accepts `user`, `password`, and an optional `attributes` map for any pool-required fields listed in `payload.required`.

**`POST /v1/login/mfa/setup`** — Required when MFA is enforced (`cognito.enforceMFA: true` or Cognito user pool setting) but not yet configured for the user. The preceding response includes `available_mfa_methods`. Only `software_token` can currently be set up.

**`POST /v1/login/mfa/setup/verify`** — Confirms TOTP enrolment initiated by the previous step. The preceding response carries the TOTP secret in `payload`; the user scans it into their authenticator app and submits the first generated code.

**`POST /v1/login/mfa/select`** — Required when the user has more than one MFA method enrolled and Cognito asks them to choose. The preceding response includes `available_mfa_methods`; submit one as `mfa_type`.

**`POST /v1/login/mfa/verify`** — Submits the one-time code for the chosen MFA method (`software_token`, `sms`, or `email`). Each login session gets `limits.mfaVerifyMaxAttempts` attempts (default 3); once exceeded, the session is invalidated and the user must restart login.

**`POST /v1/login/external`** — Log in with an authorization code from the Cognito hosted UI or an external identity provider. Completes like `/v1/login`; MFA setup is only enforced when `cognito.external.enforceMFA` is enabled.

### CSRF protection

- **Header check** — enabled while `http.csrf.headerName` is not empty. The token sent in the header must match the one issued by the start endpoint.
- **Origin check** — enabled when `http.csrf.allowedOrigins` is set. The `Origin` header of every login and update request must match one of the listed origins, otherwise `403` is returned.

---

## Masquerade mode

When `token.masquerade: true`, the client never sees real Cognito tokens. The masquerade token is an opaque reference that a trusted internal service exchanges for real tokens.

```
Browser ──► Reverse proxy / backend service
                    │
                    ├─ GET  /v1/unmask  (forwards browser cookies — cookie mode only)
                    └─ POST /v1/unmask  (sends masquerade token in body)
                              │
                         [real tokens returned as cookies or in body]
                         [appended to upstream request internally]
```

Both `/v1/unmask` endpoints are **intended for internal use only** and should not be directly reachable by end users. The refresh token is only returned when `masquerade.unmaskRefreshToken` is enabled.

In masquerade mode, token refresh is handled internally by the service. The `POST /v1/refresh` endpoint is therefore only available when masquerade mode is **disabled**.

---

## Password reset flow

Requires `password.reset.enabled: true` (default). Otherwise these endpoints return `501`.

```
POST /v1/password/reset/request   (sends email with reset link)
          │
          ▼  (user clicks link)
GET  /v1/password/reset           (validates token, redirects to frontend with session token)
          │
          ▼  (frontend collects new password + verification code)
POST /v1/password/reset/finalize  (sets new password)
```

The email link points to `GET /v1/password/reset` on this service. That endpoint redirects to `password.reset.redirectURL`, or to `password.reset.errorRedirectURL` on failure. Tokens are valid for `password.reset.tokenValidFor` minutes (default 60). The request endpoint returns the same response whether or not the email belongs to an account.

---

## Authenticated operations

The following endpoints require a valid auth token. In cookie mode the token is read automatically from the appropriate cookie; in non-cookie mode supply `Authorization: Bearer <token>`.

### Token management

**`POST /v1/refresh`** — Reissues access and ID tokens from a refresh token. Not available in masquerade mode.

**`POST /v1/logout`** — Revokes the active token and clears all auth cookies and the login session cookie. If no token is provided in the request body, it is read from the appropriate cookie (`LRTC` in standard mode, `LMTC` in masquerade mode).

### User information

**`GET /v1/profile`** — Returns basic profile information (`username`, `email`, `email_verified`, `groups`) decoded from the ID token. Lets client-side code confirm the session is valid when cookies are HTTP-only.

**`POST /v1/validate`** — Validates one or more JWT tokens and returns per-token validity. Tokens can be supplied explicitly in the request body or read from cookies.

### Update flows

Password and MFA updates work like the login flow. Each starts with a start endpoint, which returns a `csrf_token` and sets the update session cookie (`token.cookies.updateSessionCookieName`, default `US`, always http-only). Each following request must send:
- the auth token;
- the update session cookie;
- the CSRF header.

The update session is bound to the user who started it. It is closed, and its cookie cleared, when the flow completes.

**`POST /v1/password/update/start`** → **`POST /v1/password/update`** — Changes the authenticated user's password. Requires `current_password` and `new_password`.

**`POST /v1/mfa/software/update/start`** → **`POST /v1/mfa/software/update`** → **`POST /v1/mfa/update/software/verify`** — Sets up or replaces the TOTP MFA method:
1. The update step returns a TOTP secret (`code`) to be scanned into the authenticator app.
2. The verify step confirms it with the first generated code and activates the new software token.

### Client settings

**`GET /v1/settings`** — Returns the settings a client needs to adapt to this service: masquerade mode, cookie mode and cookie names, CSRF header name, whether token refresh and password reset are available, and whether MFA setup is required. No authentication required.

### MFA status

**`GET  /v1/mfa/status`** — Returns the user's current MFA configuration: enabled methods, preferred method, TOTP/SMS/email setup state, and phone number details.

---

## Rate limits

Every endpoint is rate limited per user, token, email or remote address, plus a total limit. Limits are configured under `limits.rate.<name>.limit` and `limits.rate.<name>.window` (window in seconds). Each limit is a token bucket: up to `limit` requests at once, refilled evenly over `window`. Exceeding a limit returns `429`.
