package cognito

import (
	"proxylogin/internal/manager/login/types"
)

type TaskResultFlag int

const (
	AuthInfoTaskResultFlag TaskResultFlag = 1 << iota
	RememberTaskResultFlag
	LogoutTaskResultFlag
)

func (f TaskResultFlag) Has(flag TaskResultFlag) bool {
	return f&flag == flag
}

func (f TaskResultFlag) Add(flag TaskResultFlag) TaskResultFlag {
	return f | flag
}

func (f TaskResultFlag) Remove(flag TaskResultFlag) TaskResultFlag {
	return f &^ flag
}

type MasqueradedAuth struct {
	Token string
}

type TokenAuth struct {
	Token string
}

type RefreshMethod string

var (
	RefreshMethodAuto  RefreshMethod = "auto"
	RefreshMethodAuth  RefreshMethod = "auth"
	RefreshMethodToken RefreshMethod = "token"
)

type NextStep string

const (
	NextStepNone                        NextStep = ""
	NextStepMFASetup                    NextStep = "mfa_setup"
	NextStepMFASoftwareTokenSetupVerify NextStep = "mfa_software_token_setup_verify"
	NextStepMFASelect                   NextStep = "mfa_select"
	NextStepMFASoftwareTokenVerify      NextStep = "mfa_software_token_verify"
	NextStepMFAEMailVerify              NextStep = "mfa_email_verify"
	NextStepMFASMSVerify                NextStep = "mfa_sms_verify"
	NextStepNewPassword                 NextStep = "new_password"
)

func (s NextStep) String() string {
	return string(s)
}

type NextStepResponse struct {
	NextStep NextStep    `json:"next_step,omitempty"`
	Session  string      `json:"session,omitempty"`
	Payload  interface{} `json:"payload,omitempty"`
}

type loginRequest struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Remember bool   `json:"remember"`
}

type WithValidation interface {
	Validate() types.ValidationIssues
}

func (r loginRequest) Validate() types.ValidationIssues {
	errs := make(map[string]string)
	if len(r.User) == 0 {
		errs["user"] = "User is required"
	}
	if len(r.Password) == 0 {
		errs["password"] = "Password is required"
	}
	return errs
}

type loginResponseLoginType = string

const (
	TokenSetLoginResponseLoginType   loginResponseLoginType = "token_set"
	CookiesLoginResponseLoginType    loginResponseLoginType = "cookies"
	MasqueradeLoginResponseLoginType loginResponseLoginType = "masquerade"
)

type loginResponse struct {
	LoginType loginResponseLoginType `json:"login_type"`
	LoginData interface{}            `json:"login_data"`
}

type mfaSetupRequest struct {
	Session string `json:"session"`
	User    string `json:"user"`
	MFAType string `json:"mfa_type"`
}

func (r mfaSetupRequest) Validate() types.ValidationIssues {
	errs := make(map[string]string)
	if len(r.User) == 0 {
		errs["user"] = "User is required"
	}
	if len(r.Session) == 0 {
		errs["session"] = "Session is required"
	}
	if len(r.MFAType) == 0 {
		errs["mfa_type"] = "MFAType is required"
	}
	return errs
}

type mfaSetupVerifySoftwareTokenRequest struct {
	Session string `json:"session"`
	User    string `json:"user"`
	Code    string `json:"code"`
}

func (r mfaSetupVerifySoftwareTokenRequest) Validate() types.ValidationIssues {
	errs := make(map[string]string)
	if len(r.User) == 0 {
		errs["user"] = "User is required"
	}
	if len(r.Session) == 0 {
		errs["password"] = "Session is required"
	}
	if len(r.Code) == 0 {
		errs["code"] = "Code is required"
	}
	return errs
}

type mfaSoftwareTokenVerifyRequest struct {
	Session string `json:"session"`
	User    string `json:"user"`
	Code    string `json:"code"`
}

func (r mfaSoftwareTokenVerifyRequest) Validate() types.ValidationIssues {
	errs := make(map[string]string)
	if len(r.User) == 0 {
		errs["user"] = "User is required"
	}
	if len(r.Session) == 0 {
		errs["password"] = "Session is required"
	}
	if len(r.Code) == 0 {
		errs["code"] = "Code is required"
	}
	return errs
}

type refreshTokenRequest struct {
	User  string `json:"user"`
	Token string `json:"token"`
}

func (r refreshTokenRequest) Validate() types.ValidationIssues {
	errs := make(map[string]string)
	if len(r.User) == 0 {
		errs["user"] = "User is required"
	}
	if len(r.Token) == 0 {
		errs["token"] = "Token is required"
	}
	return errs
}

type logOutRequest struct {
	Token string `json:"token"`
}

func (r logOutRequest) Validate() types.ValidationIssues {
	errs := make(map[string]string)
	if len(r.Token) == 0 {
		errs["token"] = "Token is required"
	}
	return errs
}

type satisfyPasswordUpdateRequest struct {
	Session    string            `json:"session"`
	User       string            `json:"user"`
	Password   string            `json:"password"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

func (r satisfyPasswordUpdateRequest) Validate() types.ValidationIssues {
	errs := make(map[string]string)
	if len(r.User) == 0 {
		errs["user"] = "User is required"
	}
	if len(r.Password) == 0 {
		errs["password"] = "Password is required"
	}
	if len(r.Session) == 0 {
		errs["session"] = "Session is required"
	}
	return errs
}

type updatePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (r updatePasswordRequest) Validate() types.ValidationIssues {
	errs := make(map[string]string)
	if len(r.CurrentPassword) == 0 {
		errs["current_password"] = "current password is required"
	}
	if len(r.NewPassword) == 0 {
		errs["new_password"] = "new password is required"
	}
	return errs
}

type updateMFARequest struct {
	MFAType types.MFAType `json:"mfa_type"`
}

func (r updateMFARequest) Validate() types.ValidationIssues {
	errs := make(map[string]string)
	if len(r.MFAType) == 0 {
		errs["mfa_type"] = "mfa type is required"
	}
	return errs
}

type verifyMFAUpdateRequest struct {
	Session string `json:"session"`
	Code    string `json:"code"`
}

func (r verifyMFAUpdateRequest) Validate() types.ValidationIssues {
	errs := make(map[string]string)
	if len(r.Session) == 0 {
		errs["session"] = "Session is required"
	}
	if len(r.Code) == 0 {
		errs["code"] = "Code is required"
	}
	return errs
}

type selectMFARequest struct {
	Session string        `json:"session"`
	User    string        `json:"user"`
	MFAType types.MFAType `json:"mfa_type"`
}

func (r selectMFARequest) Validate() types.ValidationIssues {
	errs := make(map[string]string)
	if len(r.Session) == 0 {
		errs["session"] = "Session is required"
	}
	if len(r.MFAType) == 0 {
		errs["mfa_type"] = "MFAType is required"
	}
	if len(r.User) == 0 {
		errs["user"] = "User is required"
	}
	return errs
}

type initiatePasswordResetRequest struct {
	Email string `json:"email"`
}

func (r initiatePasswordResetRequest) Validate() types.ValidationIssues {
	errs := make(map[string]string)
	if len(r.Email) == 0 {
		errs["email"] = "Email is required"
	}
	return errs
}

type passwordResetToken string

func (r passwordResetToken) Validate() types.ValidationIssues {
	errs := make(map[string]string)
	if len(r) == 0 {
		errs["token"] = "token is required"
	}
	return errs
}

type finalizePasswordResetRequest struct {
	User     string `json:"user"`
	Code     string `json:"code"`
	Password string `json:"password"`
}

func (r finalizePasswordResetRequest) Validate() types.ValidationIssues {
	errs := make(map[string]string)
	if len(r.User) == 0 {
		errs["user"] = "required"
	}
	if len(r.Code) == 0 {
		errs["code"] = "required"
	}
	if len(r.Password) == 0 {
		errs["password"] = "required"
	}
	return errs
}

type unmaskTokenRequest struct {
	Token string `json:"token"`
}

func (r unmaskTokenRequest) Validate() types.ValidationIssues {
	errs := make(map[string]string)
	if len(r.Token) == 0 {
		errs["token"] = "required"
	}
	return errs
}
