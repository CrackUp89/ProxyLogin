package types

type TokenSet struct {
	AccessToken  string `json:"access_token,omitempty"`
	IdToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type ErrorType string

const (
	AuthErrorType     ErrorType = "auth"
	BadDataErrorType  ErrorType = "bad_data"
	InternalErrorType ErrorType = "internal"
	OverloadErrorType ErrorType = "overload"
)

type GenericError interface {
	Error() string
	PrivateError() string
	Code() int
	Type() ErrorType
}

type InternalError struct {
	privateMessage string
	originalError  error
}

func (e *InternalError) Code() int {
	return 10000
}

func (e *InternalError) Error() string {
	return "internal error"
}

func (e *InternalError) PrivateError() string {
	return e.privateMessage
}

func (e *InternalError) Type() ErrorType {
	return InternalErrorType
}

func NewInternalError(privateMessage string, originalError error) *InternalError {
	return &InternalError{privateMessage, originalError}
}

func WrapWithInternalError(err error) *InternalError {
	return &InternalError{err.Error(), err}
}

type GenericAuthenticationError struct {
	privateMessage string
	message        string
	originalError  error
}

func (e *GenericAuthenticationError) Code() int {
	return 1000
}

func (e *GenericAuthenticationError) Error() string {
	return e.message
}

func (e *GenericAuthenticationError) PrivateError() string {
	return e.privateMessage
}

func (e *GenericAuthenticationError) Type() ErrorType {
	return AuthErrorType
}

func NewGenericAuthenticationError(privateMessage string, publicMessage string, originalError error) *GenericAuthenticationError {
	return &GenericAuthenticationError{privateMessage, publicMessage, originalError}
}

type BadRequestError struct {
	privateMessage string
	message        string
	originalError  error
}

func (e *BadRequestError) Code() int {
	return 1001
}

func (e *BadRequestError) Error() string {
	return e.message
}

func (e *BadRequestError) PrivateError() string {
	return e.privateMessage
}

func (e *BadRequestError) Type() ErrorType {
	return BadDataErrorType
}

func NewBadRequestError(privateMessage string, publicMessage string, originalError error) *BadRequestError {
	return &BadRequestError{privateMessage, publicMessage, originalError}
}

type LoginSessionExpiredOrDoesNotExistError struct{}

func (s *LoginSessionExpiredOrDoesNotExistError) Error() string {
	return "Session expired or does not exist"
}

func (s *LoginSessionExpiredOrDoesNotExistError) PrivateError() string {
	return "Session expired or does not exist"
}

func (s *LoginSessionExpiredOrDoesNotExistError) Code() int {
	return 1001
}

func (s *LoginSessionExpiredOrDoesNotExistError) Type() ErrorType {
	return BadDataErrorType
}

func NewLoginSessionExpiredOrDoesNotExistError() *LoginSessionExpiredOrDoesNotExistError {
	return &LoginSessionExpiredOrDoesNotExistError{}
}

type invalidUserOrPasswordError struct{}

func (i invalidUserOrPasswordError) Error() string {
	return "Invalid user or password"
}

func (i invalidUserOrPasswordError) PrivateError() string {
	return "Invalid user or password"
}

func (i invalidUserOrPasswordError) Code() int {
	return 1002
}

func (i invalidUserOrPasswordError) Type() ErrorType {
	return AuthErrorType
}

var InvalidUserOrPasswordError = invalidUserOrPasswordError{}

type passwordHistoryError struct{}

func (i passwordHistoryError) Error() string {
	return "can not reuse password"
}

func (i passwordHistoryError) PrivateError() string {
	return "can not reuse password"
}

func (i passwordHistoryError) Code() int {
	return 1003
}

func (i passwordHistoryError) Type() ErrorType {
	return BadDataErrorType
}

var PasswordHistoryError = passwordHistoryError{}

type invalidNewPasswordError struct{}

func (i invalidNewPasswordError) Error() string {
	return "invalid new password"
}

func (i invalidNewPasswordError) PrivateError() string {
	return "invalid new password"
}

func (i invalidNewPasswordError) Code() int {
	return 1004
}

func (i invalidNewPasswordError) Type() ErrorType {
	return BadDataErrorType
}

var InvalidNewPasswordError = invalidNewPasswordError{}

type invalidVerificationCodeError struct{}

func (i invalidVerificationCodeError) Error() string {
	return "invalid verification code"
}

func (i invalidVerificationCodeError) PrivateError() string {
	return "invalid verification code"
}

func (i invalidVerificationCodeError) Code() int {
	return 1005
}

func (i invalidVerificationCodeError) Type() ErrorType {
	return AuthErrorType
}

var InvalidVerificationCodeError = invalidVerificationCodeError{}
