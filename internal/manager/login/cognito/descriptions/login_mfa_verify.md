Submits a one-time code to complete the MFA step of an in-progress login flow.

This endpoint is called after receiving a `next_step` of `mfa_software_token_verify`, `mfa_sms_verify`, or `mfa_email_verify` — typically following a `mfa_select` step. The `code` field accepts the OTP appropriate for the chosen method (TOTP from an authenticator app, or a code delivered via SMS / email).

**Request fields**:
- `session` *(required)* — login session key returned by the previous step.
- `user` *(required)* — username or email address.
- `code` *(required)* — one-time verification code.

**Attempt limit**: a maximum of 3 verification attempts are allowed per login session. On the third failed attempt the session is invalidated and the user must restart the login flow from the beginning.

**On success**: the login flow completes and tokens are delivered using the same mechanism as the `/v1/login` endpoint (cookies or response body, depending on configuration).
