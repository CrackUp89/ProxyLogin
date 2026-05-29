package types

type MFAType string

const (
	MFATypeSoftwareToken MFAType = "software_token"
	MFATypeSMS           MFAType = "sms"
	MFATypeEMAIL         MFAType = "email"
)

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
