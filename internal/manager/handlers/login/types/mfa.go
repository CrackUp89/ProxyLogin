package types

type MFASetupType string

const (
	MFASetupTypeSoftwareToken MFASetupType = "software_token"
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

var InvalidMFASoftwareTokenError = invalidMFASoftwareTokenError{}
