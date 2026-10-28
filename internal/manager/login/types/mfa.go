package types

type MFAType string

const (
	MFATypeSoftwareToken MFAType = "software_token"
	MFATypeSMS           MFAType = "sms"
	MFATypeEMAIL         MFAType = "email"
)

type MFAStatus struct {
	MFAEnabled      bool      `json:"mfa_enabled"`
	MFAMethods      []MFAType `json:"mfa_methods" enum:"software_token,sms,email" doc:"MFA methods enrolled by the user"`
	PreferredMFA    MFAType   `json:"preferred_mfa" doc:"Preferred MFA method: software_token, sms or email. Empty if none is set"`
	HasPhoneNumber  bool      `json:"has_phone_number"`
	PhoneVerified   bool      `json:"phone_verified"`
	PhoneNumber     string    `json:"phone_number"`
	TOTPConfigured  bool      `json:"totp_configured"`
	SMSConfigured   bool      `json:"sms_configured"`
	EMAILConfigured bool      `json:"email_configured"`
}
