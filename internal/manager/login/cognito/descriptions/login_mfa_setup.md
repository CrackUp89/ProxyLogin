Initiates MFA enrolment as part of the login flow.

This endpoint is called after receiving a `next_step: mfa_setup` response. That step is triggered when MFA is required but not yet configured for the user — either because the Cognito user pool enforces MFA, or because `cognito.enforceMFA` is enabled. The preceding response includes an `available_mfa_methods` list in its payload.

Requires the login session cookie and CSRF header from `/v1/login/start`.

**Request fields**:
- `user` *(required)* — username or email address.
- `mfa_type` *(required)* — MFA method to enrol. Only `software_token` is currently supported; any other value returns `400`.

**Response**: `next_step: mfa_token_setup_verify` with the TOTP secret as `payload`. The client should present this secret (or a QR code derived from it) to the user so they can configure their authenticator app before calling `/v1/login/mfa/setup/verify`.
