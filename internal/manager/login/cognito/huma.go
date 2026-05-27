package cognito

import (
	loginTypes "proxylogin/internal/manager/login/types"
)

// NextStepAuthTaskResponse Typed AuthTaskResponse variant with next login step to describe Huma return types
type NextStepAuthTaskResponse[T any] struct {
	NextStep T `json:"next_step,omitempty" doc:"Next step required to complete login"`
}

// ---------------------------------------------------------------------------
// Shared payload types
// ---------------------------------------------------------------------------

// MFAMethodListPayload is the payload for steps that present a list of MFA methods.
type MFAMethodListPayload struct {
	AvailableMFAMethods []loginTypes.MFAType `json:"available_mfa_methods" doc:"Available MFA methods"`
}

// NewPasswordPayload is the payload for the new_password challenge.
type NewPasswordPayload struct {
	Required string `json:"required,omitempty" doc:"Required attributes for the new password challenge"`
}

// ---------------------------------------------------------------------------
// Per-step descriptors
// ---------------------------------------------------------------------------

// LoginStepMFASetup describes the mfa_setup next step (choose an MFA method to enrol).
type LoginStepMFASetup struct {
	Step    NextStep              `json:"step,omitempty" enum:"mfa_setup" default:"mfa_setup" doc:"Name of the next login step"`
	Session string                `json:"session,omitempty" doc:"Current authentication session"`
	Payload *MFAMethodListPayload `json:"payload,omitempty" doc:"Available MFA methods to set up"`
}

// LoginStepMFASoftwareTokenSetupVerify describes the mfa_software_token_setup_verify step.
// Payload contains the TOTP secret code the client uses to configure their authenticator app.
type LoginStepMFASoftwareTokenSetupVerify struct {
	Step    NextStep `json:"step,omitempty" enum:"mfa_software_token_setup_verify" default:"mfa_software_token_setup_verify" doc:"Name of the next login step"`
	Session string   `json:"session,omitempty" doc:"Current authentication session"`
	Payload string   `json:"payload,omitempty" doc:"TOTP secret code for authenticator app configuration"`
}

// LoginStepMFASelect describes the mfa_select step (pick from already-enrolled MFA methods).
type LoginStepMFASelect struct {
	Step    NextStep              `json:"step,omitempty" enum:"mfa_select" default:"mfa_select" doc:"Name of the next login step"`
	Session string                `json:"session,omitempty" doc:"Current authentication session"`
	Payload *MFAMethodListPayload `json:"payload,omitempty" doc:"Available MFA methods to choose from"`
}

// LoginStepMFASoftwareTokenVerify describes the mfa_software_token_verify step.
type LoginStepMFASoftwareTokenVerify struct {
	Step    NextStep `json:"step,omitempty" enum:"mfa_software_token_verify" default:"mfa_software_token_verify" doc:"Name of the next login step"`
	Session string   `json:"session,omitempty" doc:"Current authentication session"`
}

// LoginStepMFAEmailVerify describes the mfa_email_verify step.
type LoginStepMFAEmailVerify struct {
	Step    NextStep `json:"step,omitempty" enum:"mfa_email_verify" default:"mfa_email_verify" doc:"Name of the next login step"`
	Session string   `json:"session,omitempty" doc:"Current authentication session"`
}

// LoginStepMFASMSVerify describes the mfa_sms_verify step.
type LoginStepMFASMSVerify struct {
	Step    NextStep `json:"step,omitempty" enum:"mfa_sms_verify" default:"mfa_sms_verify" doc:"Name of the next login step"`
	Session string   `json:"session,omitempty" doc:"Current authentication session"`
}

// LoginStepNewPassword describes the new_password challenge step.
type LoginStepNewPassword struct {
	Step    NextStep            `json:"step,omitempty" enum:"new_password" default:"new_password" doc:"Name of the next login step"`
	Session string              `json:"session,omitempty" doc:"Current authentication session"`
	Payload *NewPasswordPayload `json:"payload,omitempty" doc:"Password requirements"`
}
