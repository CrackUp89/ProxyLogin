Submits a one-time code to complete the MFA step of an in-progress login flow.

This endpoint is called after receiving a `next_step` of `mfa_software_token_verify`, `mfa_sms_verify`, or `mfa_email_verify` — either directly from `/v1/login` or after a `mfa_select` step. The `code` field accepts the OTP appropriate for the method (TOTP from an authenticator app, or a code delivered via SMS / email).

Requires the login session cookie and CSRF header from `/v1/login/start`.

**Request fields**:
- `user` *(required)* — username or email address.
- `code` *(required)* — one-time verification code.

**Attempt limit**: each user gets `limits.mfaVerifyMaxAttempts` verification attempts (default 3). The counter resets on a successful verification and on every `/v1/login` call. Once the limit is exceeded, the login session is invalidated, `401` is returned, and the user must restart the login flow from `/v1/login/start`.

**On success**: the login flow completes and tokens are delivered using the same mechanism as the `/v1/login` endpoint (cookies or response body, depending on configuration).
