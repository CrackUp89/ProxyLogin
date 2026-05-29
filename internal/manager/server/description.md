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
Real tokens are never exposed to the client. Instead a single opaque masquerade token is issued via the `token.cookies.masqueradedCookieName` cookie (default `LMTC`). It can be exchanged for real tokens by a trusted backend service or reverse proxy via `GET /v1/unmask` (cookie source) or `POST /v1/unmask` (body source) — see [Masquerade mode](#masquerade-mode) below.

**Non-cookie mode** (`token.cookies.enabled: false`):
All tokens are returned directly in the response body.

Cookie names are prefixed with `__Secure-` when `token.cookies.secure` is `true`.

---

## Login flow

Login is a multi-step process. Each response either completes authentication (tokens are delivered) or returns a `next_step` object indicating what the client must do next. Pass the `session` key from each response into the following step.

```
POST /v1/login
      │
      ├─ next_step: new_password ──────────────────► POST /v1/login/password/update
      │                                                      │
      ├─ next_step: mfa_setup ─────────────────────► POST /v1/login/mfa/setup
      │       │                                              │
      │       └─ next_step: mfa_software_token_setup_verify  │
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

**`POST /v1/login`** — Submit username and password. Accepts an optional `remember` flag that controls cookie expiry.

**`POST /v1/login/password/update`** — Required when Cognito returns a `new_password` challenge (administratively set or expired password). Accepts `session`, `user`, `password`, and an optional `attributes` map for any pool-required fields listed in `payload.required`.

**`POST /v1/login/mfa/setup`** — Required when MFA is enforced (`cognito.enforceMFA: true` or Cognito user pool setting) but not yet configured for the user. The preceding response includes `available_mfa_methods`; submit one of those values as `mfa_type`.

**`POST /v1/login/mfa/setup/verify`** — Confirms TOTP enrolment initiated by the previous step. The preceding response carries the TOTP secret in `payload`; the user scans it into their authenticator app and submits the first generated code.

**`POST /v1/login/mfa/select`** — Required when the user has more than one MFA method enrolled and Cognito asks them to choose. The preceding response includes `available_mfa_methods`; submit one as `mfa_type`.

**`POST /v1/login/mfa/verify`** — Submits the one-time code for the chosen MFA method (`software_token`, `sms`, or `email`). Limited to **3 attempts** per session; on the third failure the session is invalidated and the user must restart login.

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

Both `/v1/unmask` endpoints are **intended for internal use only** and should not be directly reachable by end users.

In masquerade mode, token refresh is handled internally by the service. The `POST /v1/refresh` endpoint is therefore only available when masquerade mode is **disabled**.

---

## Password reset flow

Requires `password.reset.enabled: true`.

```
POST /v1/password/reset/request   (sends email with reset link)
          │
          ▼  (user clicks link)
GET  /v1/password/reset           (validates token, redirects to frontend with session token)
          │
          ▼  (frontend collects new password + verification code)
POST /v1/password/reset/finalize  (sets new password)
```

The reset link format is configured via `password.reset.redirectURL`. The token is valid for `password.reset.tokenValidFor` minutes (default 60). The request endpoint is rate-limited to **1 request per 5 minutes** per email address.

---

## Authenticated operations

The following endpoints require a valid auth token. In cookie mode the token is read automatically from the appropriate cookie; in non-cookie mode supply `Authorization: Bearer <token>`.

### Token management

**`POST /v1/refresh`** — Reissues access and ID tokens from a refresh token. Not available in masquerade mode.

**`POST /v1/logout`** — Revokes the active token and clears all auth cookies. If no token is provided in the request body, it is read from the appropriate cookie (`LRTC` in standard mode, `LMTC` in masquerade mode).

### User information

**`GET /v1/profile`** — Returns basic profile information (`username`, `email`, `email_verified`, `groups`) decoded from the token. Useful in masquerade mode where JavaScript cannot inspect HTTP-only cookies, making this the only way for client-side code to confirm the session is valid.

**`POST /v1/validate`** — Validates one or more JWT tokens and returns per-token validity. Tokens can be supplied explicitly in the request body or read from cookies.

### Password

**`POST /v1/password/update`** — Changes the authenticated user's password. Requires `current_password` and `new_password`.

### MFA management

**`GET  /v1/mfa/status`** — Returns the user's current MFA configuration: enabled methods, preferred method, TOTP/SMS/email setup state, and phone number details.

**`POST /v1/mfa/software/update`** — Begins TOTP MFA setup or replacement for an already authenticated user. Returns a TOTP secret (`code`) to be scanned into the authenticator app.

**`POST /v1/mfa/update/software/verify`** — Confirms the TOTP setup by verifying the first generated code. Activates the new software token, replacing any previously configured one.
