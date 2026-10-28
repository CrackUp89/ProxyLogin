Returns the MFA configuration for the authenticated user.

Requires a valid auth token via cookie or `Authorization: Bearer` header.

**Response fields**:
- `mfa_enabled` — whether MFA is currently active for the user.
- `mfa_methods` — list of MFA methods enrolled by the user: `software_token`, `sms`, `email`.
- `preferred_mfa` — the user's preferred MFA method, in the same format; empty if none is set.
- `totp_configured` — whether a software token (TOTP) authenticator app is configured.
- `sms_configured` — whether SMS-based MFA is configured.
- `email_configured` — whether email-based MFA is configured.
- `has_phone_number` — whether a phone number is associated with the account.
- `phone_verified` — whether the associated phone number has been verified.
- `phone_number` — the phone number associated with the account.
