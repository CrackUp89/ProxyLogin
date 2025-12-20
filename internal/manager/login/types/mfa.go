package types

type MFAType string

const (
	MFATypeSoftwareToken MFAType = "software_token"
	MFATypeSMS           MFAType = "sms"
	MFATypeEMAIL         MFAType = "email"
)

type invalidMFASetupSoftwareTokenError struct{}

func (e invalidMFASetupSoftwareTokenError) Code() int {
	return 2000
}

func (e invalidMFASetupSoftwareTokenError) Error() string {
	return "MFA code invalid"
}

func (e invalidMFASetupSoftwareTokenError) PrivateError() string {
	return "MFA code invalid"
}

var InvalidMFASetupSoftwareTokenError = invalidMFASetupSoftwareTokenError{}

type invalidMFASoftwareTokenError struct{}

func (e invalidMFASoftwareTokenError) Code() int {
	return 2001
}

func (e invalidMFASoftwareTokenError) PrivateError() string {
	return "Invalid MFA Software Token"
}

func (e invalidMFASoftwareTokenError) Error() string {
	return "Invalid MFA Software Token"
}

var InvalidMFACodeError = invalidMFASoftwareTokenError{}

type MFAStatus struct {
	MFAEnabled      bool     `json:"mfa_enabled"`
	MFAMethods      []string `json:"mfa_methods"`
	PreferredMFA    string   `json:"preferred_mfa"`
	HasPhoneNumber  bool     `json:"has_phone_number"`
	PhoneVerified   bool     `json:"phone_verified"`
	PhoneNumber     string   `json:"phone_number"`
	TOTPConfigured  bool     `json:"totp_configured"`
	SMSConfigured   bool     `json:"sms_configured"`
	EMAILConfigured bool     `json:"email_configured"`
}
