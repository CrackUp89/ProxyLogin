package cognito

import _ "embed"

//go:embed descriptions/login_start.md
var descLoginStart string

//go:embed descriptions/login.md
var descLogin string

//go:embed descriptions/validate.md
var descValidate string

//go:embed descriptions/login_mfa_setup.md
var descLoginMFASetup string

//go:embed descriptions/login_mfa_setup_verify.md
var descLoginMFASetupVerify string

//go:embed descriptions/login_mfa_verify.md
var descLoginMFAVerify string

//go:embed descriptions/login_mfa_select.md
var descLoginMFASelect string

//go:embed descriptions/login_password_update.md
var descLoginPasswordUpdate string

//go:embed descriptions/logout.md
var descLogout string

//go:embed descriptions/refresh_tokens.md
var descRefreshTokens string

//go:embed descriptions/password_update.md
var descPasswordUpdate string

//go:embed descriptions/password_update_start.md
var descPasswordUpdateStart string

//go:embed descriptions/mfa_software_token_update_start.md
var descMFASoftwareTokenUpdateStart string

//go:embed descriptions/mfa_status.md
var descMFAStatus string

//go:embed descriptions/mfa_software_token_update.md
var descMFASoftwareTokenUpdate string

//go:embed descriptions/mfa_software_token_update_verify.md
var descMFASoftwareTokenUpdateVerify string

//go:embed descriptions/password_reset_request.md
var descPasswordResetRequest string

//go:embed descriptions/password_reset_validate.md
var descPasswordResetValidate string

//go:embed descriptions/password_reset_finalize.md
var descPasswordResetFinalize string

//go:embed descriptions/unmask_token_cookie.md
var descUnmaskTokenCookie string

//go:embed descriptions/unmask_token.md
var descUnmaskToken string

//go:embed descriptions/get_profile.md
var descGetProfile string

//go:embed descriptions/external_login.md
var descExternalLogin string

//go:embed descriptions/settings.md
var descSettings string
