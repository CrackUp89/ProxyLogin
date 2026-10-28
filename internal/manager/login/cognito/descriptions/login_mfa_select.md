Selects the MFA method the user wishes to use to continue an in-progress login flow.

This endpoint is called after receiving a `next_step: mfa_select` response, which carries an `available_mfa_methods` list in its payload. The client must pick one of those values and submit it here.

Requires the login session cookie and CSRF header from `/v1/login/start`.

**Request fields**:
- `user` *(required)* — username or email address.
- `mfa_type` *(required)* — MFA method to use; must be one of the values from `available_mfa_methods` in the preceding `mfa_select` step. Supported values: `software_token`, `sms`, `email`.

**Response**: a `next_step` indicating the verification step for the chosen method (`mfa_software_token_verify`, `mfa_sms_verify` or `mfa_email_verify`).
