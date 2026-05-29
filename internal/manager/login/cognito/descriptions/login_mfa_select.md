Selects the MFA method the user wishes to use to continue an in-progress login flow.

This endpoint is called after receiving a `next_step: mfa_select` response, which carries an `available_mfa_methods` list in its payload. The client must pick one of those values and submit it here.

**Request fields**:
- `session` *(required)* — login session key returned by the previous step.
- `user` *(required)* — username or email address.
- `mfa_type` *(required)* — MFA method to use; must be one of the values from `available_mfa_methods` in the preceding `mfa_select` step. Supported values: `software_token`, `sms`, `email`.

**Response**: a `next_step` indicating the verification step for the chosen method (e.g. `mfa_software_token_verify`, `mfa_sms_verify`, `mfa_email_verify`).
