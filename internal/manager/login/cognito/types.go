package cognito

import (
	"context"
	"fmt"
	"net/http"
	"proxylogin/internal/manager/login/types"
	"reflect"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

type withToken struct {
	Token string
}
type MasqueradedAuth struct {
	withToken
}

type TokenAuth struct {
	withToken
}

type RefreshMethod string

var (
	RefreshMethodAuto  RefreshMethod = "auto"
	RefreshMethodAuth  RefreshMethod = "auth"
	RefreshMethodToken RefreshMethod = "token"
)

type NextStep string

const (
	NextStepLogin                       NextStep = "login"
	NextStepMFASetup                    NextStep = "mfa_setup"
	NextStepMFASoftwareTokenSetupVerify NextStep = "mfa_token_setup_verify"
	NextStepMFASelect                   NextStep = "mfa_select"
	NextStepMFASoftwareTokenVerify      NextStep = "mfa_software_token_verify"
	NextStepMFAEMailVerify              NextStep = "mfa_email_verify"
	NextStepMFASMSVerify                NextStep = "mfa_sms_verify"
	NextStepNewPassword                 NextStep = "new_password"
)

type NextStepVariant string

const (
	NextStepVariantDefault        NextStepVariant = ""
	NextStepVariantMFAEnforcement NextStepVariant = "mfa_enforcement"
)

func (s NextStep) String() string {
	return string(s)
}

var defaultErrorResponseSchema *huma.Schema
var loginStepSchemas []*huma.Schema
var authResultsSchemas []*huma.Schema

func registerSharedSchemas(api huma.API) {
	registry := api.OpenAPI().Components.Schemas

	defaultErrorResponseSchema = registry.Schema(reflect.TypeOf(huma.ErrorModel{}), true, "")

	addSchema := func(t reflect.Type, title, description string) *huma.Schema {
		ref := registry.Schema(t, true, "")
		if ref == nil {
			panic("unable to register schema for " + t.Name())
		}
		if actual := registry.SchemaFromRef(ref.Ref); actual != nil {
			actual.Title = title
			actual.Description = description
		}
		return ref
	}

	loginStepSchemas = []*huma.Schema{
		addSchema(reflect.TypeOf(LoginStepMFASetup{}),
			"Next login step - MFA setup",
			"User must choose and set up an MFA method"),
		addSchema(reflect.TypeOf(LoginStepMFASoftwareTokenSetupVerify{}),
			"Next login step - Software token setup verify",
			"User must enter the TOTP code to complete authenticator app setup"),
		addSchema(reflect.TypeOf(LoginStepMFASelect{}),
			"Next login step - Select MFA method",
			"User must select which enrolled MFA method to use"),
		addSchema(reflect.TypeOf(LoginStepMFASoftwareTokenVerify{}),
			"Next login step - Software token verify",
			"User must provide a TOTP code from their authenticator app"),
		addSchema(reflect.TypeOf(LoginStepMFAEmailVerify{}),
			"Next login step - Email OTP verify",
			"User must provide the OTP sent to their email"),
		addSchema(reflect.TypeOf(LoginStepMFASMSVerify{}),
			"Next login step - SMS OTP verify",
			"User must provide the OTP sent via SMS"),
		addSchema(reflect.TypeOf(LoginStepNewPassword{}),
			"Next login step - New password required",
			"User must set a new password to complete login"),
	}

	authResultsSchemas = []*huma.Schema{
		addSchema(reflect.TypeOf(loginResponseTokenSet{}),
			"Login successful - Token set",
			"Login is successful. Returned if token.cookies.enabled = false and token.masquerade = false"),
		addSchema(reflect.TypeOf(loginResponseMasquerade{}),
			"Login successful - Masqueraded token",
			"Login is successful. Returned if token.cookies.enabled = false and token.masquerade = true"),
	}
}

type NextLoginStepResponse struct {
	Step    NextStep    `json:"step,omitempty" enum:"mfa_setup,mfa_token_setup_verify,mfa_select,mfa_software_token_verify,mfa_email_verify,mfa_sms_verify,new_password"`
	Payload interface{} `json:"payload,omitempty"`
}

type LoginStartResponseBody struct {
	CSRFToken string `json:"csrf_token" doc:"Send this in the CSRF header with every following login flow request"`
}

type LoginStartResponseOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      LoginStartResponseBody
}

type AuthTaskResponse struct {
	NextStep   NextLoginStepResponse `json:"next_step,omitempty"`
	AuthResult interface{}           `json:"auth_result,omitempty"`
}

func (t AuthTaskResponse) TransformSchema(r huma.Registry, s *huma.Schema) *huma.Schema {
	s.Title = "Login operation result"
	s.Description = "Returns next login step required to finish authentication or authentication result.\n `next_step` and `auth_result` are mutually exclusive."
	s.Properties["next_step"] = &huma.Schema{
		OneOf: loginStepSchemas,
	}
	s.Properties["auth_result"] = &huma.Schema{
		OneOf: authResultsSchemas,
	}
	return s
}

type TokenValidationTaskResponse struct {
	Tokens          map[string]bool   `json:"tokens"`
	ValidationError map[string]string `json:"validation_errors,omitempty"`
}

func (t TokenValidationTaskResponse) TransformSchema(r huma.Registry, s *huma.Schema) *huma.Schema {
	//s.Title = "Login operation result"
	//s.Description = "Returns next login step required to finish authentication or authentication result.\n `next_step` and `auth_result` are mutually exclusive."
	//s.Properties["next_step"] = &huma.Schema{
	//	OneOf: loginStepSchemas,
	//}
	//s.Properties["auth_result"] = &huma.Schema{
	//	OneOf: authResultsSchemas,
	//}
	return s
}

type TokenValidationTaskOutput struct {
	Status int
	Body   *TokenValidationTaskResponse
}

type loginResponseLoginType = string

const (
	TokenSetLoginResponseLoginType   loginResponseLoginType = "token_set"
	MasqueradeLoginResponseLoginType loginResponseLoginType = "masquerade"
)

type loginResponseTokenSet struct {
	LoginType loginResponseLoginType `json:"login_type" default:"token_set" enum:"token_set"`
	LoginData *types.AuthTokenSet    `json:"login_data,omitempty" doc:"Token set. If not present than was delivered via cookies"`
}

func (l *loginResponseTokenSet) GetLoginType() loginResponseLoginType {
	return l.LoginType
}

func newLoginResponseTokenSet(tokenSet *types.AuthTokenSet) *loginResponseTokenSet {
	return &loginResponseTokenSet{
		LoginType: TokenSetLoginResponseLoginType,
		LoginData: tokenSet,
	}
}

type loginResponseMasquerade struct {
	LoginType loginResponseLoginType  `json:"login_type" default:"masquerade" enum:"masquerade"`
	LoginData *types.MasqueradedToken `json:"login_data,omitempty" doc:"Masqueraded token. If not present than was delivered via cookies"`
}

func (l *loginResponseMasquerade) GetLoginType() loginResponseLoginType {
	return l.LoginType
}

func newLoginResponseMasquerade(token *types.MasqueradedToken) *loginResponseMasquerade {
	return &loginResponseMasquerade{
		LoginType: MasqueradeLoginResponseLoginType,
		LoginData: token,
	}
}

type loginResponse interface {
	GetLoginType() loginResponseLoginType
}

// ---------------------------------------------------------------------------
// Huma output wrappers
// ---------------------------------------------------------------------------

type TaskResponse[T any] interface {
	SetSetCookie(cookies []http.Cookie)
	GetSetCookie() []http.Cookie
	SetBody(body T)
	GetBody() T
}
type TaskResponseOutput[T any] struct {
	Body      T
	SetCookie []http.Cookie `header:"Set-Cookie"`
}

type GenericTaskResponseOutput = TaskResponseOutput[interface{}]

func (t *TaskResponseOutput[T]) SetBody(body T) {
	t.Body = body
}

func (t *TaskResponseOutput[T]) GetBody() T {
	return t.Body
}

// RedirectOutput is used for 302 redirects (password reset).
type RedirectOutput struct {
	Status   int    `header:"Status"`
	Location string `header:"Location"`
}

// EmptyOutput is used for endpoints that return empty bodies.
type EmptyOutput struct {
	Body struct{}
}

// ---------------------------------------------------------------------------
// Validation helpers for huma Resolve pattern
// ---------------------------------------------------------------------------

func validationIssuestoHumaErrors(issues types.ValidationIssues) []error {
	errs := make([]error, 0, len(issues))
	for field, msg := range issues {
		errs = append(errs, &huma.ErrorDetail{
			Location: fmt.Sprintf("body.%s", field),
			Message:  msg,
			Value:    "",
		})
	}
	return errs
}

// ---------------------------------------------------------------------------
// Request types with huma input wrappers
// ---------------------------------------------------------------------------

type loginRequest struct {
	User     string `json:"user" minLength:"1" doc:"Username"`
	Password string `json:"password" minLength:"1" doc:"Password"`
	Remember bool   `json:"remember" doc:"Remember user session" required:"false"`
}

type LoginInput struct {
	Body loginRequest
}

type externalLoginRequest struct {
	Code     string `json:"code" minLength:"1" doc:"Code received from external authentication authority"`
	Remember bool   `json:"remember" doc:"Remember user session" required:"false"`
}

type ExternalLoginInput struct {
	Body externalLoginRequest
}

type mfaSetupRequest struct {
	User    string `json:"user" minLength:"1" doc:"Username"`
	MFAType string `json:"mfa_type" minLength:"1" doc:"MFA type to set up"`
}

type MFASetupInput struct {
	Body mfaSetupRequest
}

type mfaSetupVerifyTokenRequest struct {
	User string `json:"user" minLength:"1" doc:"Username"`
	Code string `json:"code" minLength:"1" doc:"Verification code"`
}

type MFASetupVerifyTokenInput struct {
	Body mfaSetupVerifyTokenRequest
}

type mfaTokenVerifyRequest struct {
	User string `json:"user" minLength:"1" doc:"Username"`
	Code string `json:"code" minLength:"1" doc:"Verification code"`
}

type MFATokenVerifyInput struct {
	Body mfaTokenVerifyRequest
}

type refreshTokenRequest struct {
	User     string  `json:"user" doc:"Username"`
	Token    *string `json:"token,omitempty"  doc:"Refresh token" required:"false"`
	Remember *bool   `json:"remember,omitempty" doc:"Remember user session" required:"false"`
}

type RefreshTokenInput struct {
	Body refreshTokenRequest
}

type logOutRequest struct {
	Token string `json:"token,omitempty" required:"false" doc:"Refresh token to revoke"`
}

type LogOutInput struct {
	Body logOutRequest
}

type satisfyPasswordUpdateRequest struct {
	User       string            `json:"user" minLength:"1" doc:"Username"`
	Password   string            `json:"password" minLength:"1" doc:"New password"`
	Attributes map[string]string `json:"attributes,omitempty" doc:"Additional user attributes"`
}

type SatisfyPasswordUpdateInput struct {
	Body satisfyPasswordUpdateRequest
}

type updatePasswordRequest struct {
	CurrentPassword string `json:"current_password" minLength:"1" doc:"Current password"`
	NewPassword     string `json:"new_password" minLength:"1" doc:"New password"`
}

type UpdatePasswordInput struct {
	Body updatePasswordRequest
}

type verifyMFAUpdateRequest struct {
	Code string `json:"code" minLength:"1" doc:"TOTP verification code"`
}

type VerifyMFASoftwareTokenUpdateInput struct {
	Body verifyMFAUpdateRequest
}

type selectMFARequest struct {
	User    string        `json:"user" minLength:"1" doc:"Username"`
	MFAType types.MFAType `json:"mfa_type" minLength:"1" doc:"MFA type to select"`
}

type SelectMFAInput struct {
	Body selectMFARequest
}

type initiatePasswordResetRequest struct {
	Email string `json:"email" minLength:"1" doc:"Email address"`
}

type InitiatePasswordResetInput struct {
	Body initiatePasswordResetRequest
}

type passwordResetToken string

func (r passwordResetToken) Validate() types.ValidationIssues {
	errs := make(map[string]string)
	if len(r) == 0 {
		errs["token"] = "token is required"
	}
	return errs
}

type PasswordResetInput struct {
	Token string `query:"token" required:"true" doc:"Password reset token"`
}

func (i *PasswordResetInput) Resolve(ctx context.Context, prefix *huma.PathBuffer) []error {
	if len(i.Token) == 0 {
		return []error{&huma.ErrorDetail{
			Location: "query.token",
			Message:  "token is required",
			Value:    i.Token,
		}}
	}
	return nil
}

type finalizePasswordResetRequest struct {
	Token    string `json:"token" minLength:"1" doc:"Session token"`
	Code     string `json:"code" minLength:"1" doc:"Reset verification code"`
	Password string `json:"password" minLength:"1" doc:"New password"`
}

type FinalizePasswordResetInput struct {
	Body finalizePasswordResetRequest
}

type UnmaskTokenInputGet struct {
	Remember bool `json:"remember" default:"false" doc:"If cookies are enabled - sets cookies expiration date" query:"remember"`
}

func (t UnmaskTokenInputGet) TransformSchema(r huma.Registry, s *huma.Schema) *huma.Schema {
	return s
}

type unmaskTokenInputBody struct {
	Token    string `json:"token" minLength:"1" doc:"Masqueraded token to unmask"`
	Remember bool   `json:"remember" default:"false" required:"false" doc:"If cookies are enabled - sets cookies expiration date"`
}

type UnmaskTokenInputPost struct {
	Body unmaskTokenInputBody
}

type UnmaskTokenResultBody struct {
	AccessToken  string `json:"access_token,omitempty" doc:"Access token"`
	IdToken      string `json:"id_token,omitempty" doc:"Id token"`
	RefreshToken string `json:"refresh_token,omitempty" doc:"Refresh token. Only present if token refresh is enabled and unmask refresh token is enabled"`
}

type UnmaskTokenResult struct {
	Body      UnmaskTokenResultBody `doc:"If cookies are disabled - contains authentication token set"`
	SetCookie []http.Cookie         `header:"Set-Cookie"`
}

// WithValidation is kept for backward compat but no longer used by handlers.
type WithValidation interface {
	Validate() types.ValidationIssues
}

func resolveValidationIssues(issues types.ValidationIssues) []error {
	if len(issues) == 0 {
		return nil
	}

	errs := make([]error, 0, len(issues))
	for field, msg := range issues {
		parts := strings.SplitN(field, ".", 2)
		location := "body." + parts[0]
		if len(parts) > 1 {
			location = "body." + field
		}
		errs = append(errs, &huma.ErrorDetail{
			Location: location,
			Message:  msg,
			Value:    "",
		})
	}
	return errs
}

type UserIdTokenProfile struct {
	Groups        []string `json:"groups" required:"true" nullable:"false"`
	Username      string   `json:"username"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
}

type returnUnauthorized string

const (
	DoNotReturnUnauthorized = "no"
	ReturnUnauthorizedAny   = "any"
	ReturnUnauthorizedAll   = "all"
)

type tokenValidationRequest struct {
	Tokens             map[string]string  `json:"tokens" required:"false" doc:"Optional dictionary containing tokens to check. If present, auth and id tokens inside headers are ignored."`
	ReturnErrors       bool               `json:"return_errors" required:"false" doc:"Return token validation errors." default:"true"`
	ReturnUnauthorized returnUnauthorized `json:"return_unauthorized" required:"false" doc:"Decides if method returns a 401 status in case of all or any of the tokens are invalid" default:"any" enum:"no,all,any"`
}

type TokenValidationInput struct {
	Body tokenValidationRequest
}
