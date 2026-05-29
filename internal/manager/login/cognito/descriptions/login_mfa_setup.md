Initiates MFA enrolment as part of the login flow.

This endpoint is called after receiving a `next_step: mfa_setup` response. That step is triggered when MFA is required but not yet configured for the user — either because the Cognito user pool enforces MFA, or because the `cognito.enforceMFA` parameter is enabled. The preceding response includes an `available_mfa_methods` list in its payload; the client must pick one of those values and submit it here.

**Request fields**:
- `session` *(required)* — login session key returned by the previous step.
- `user` *(required)* — username or email address.
- `mfa_type` *(required)* — MFA method to enrol; must be one of the values from `available_mfa_methods` in the preceding `mfa_setup` step. Supported values: `software_token`, `sms`, `email`.

**Response**: `next_step: mfa_software_token_setup_verify` with the TOTP secret in `payload`. The client should present this secret (or a QR code derived from it) to the user so they can configure their authenticator app before calling `/v1/login/mfa/setup/verify`.
