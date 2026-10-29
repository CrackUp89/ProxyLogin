package types

import (
	"errors"
	"time"
)

type TokenType string

const (
	AuthTokenType    TokenType = "auth"
	IDTokenType      TokenType = "id"
	RefreshTokenType TokenType = "refresh"
)

const (
	DefaultInternalErrorCode = 100
	DefaultAuthErrorCode     = 1000
	DefaultBadRequestCode    = 2000
)

type AuthTokenSet struct {
	AccessToken         string     `json:"access_token,omitempty" required:"true" doc:"Access token"`
	AccessTokenExpires  *time.Time `json:"access_token_expires,omitempty" required:"true"`
	IdToken             string     `json:"id_token,omitempty" required:"true" doc:"Id token"`
	IdTokenExpires      *time.Time `json:"id_token_expires,omitempty" required:"true"`
	RefreshToken        string     `json:"refresh_token,omitempty" doc:"Refresh token. Not present after a token refresh unless Cognito refresh token rotation is enabled"`
	RefreshTokenExpires *time.Time `json:"refresh_token_expires,omitempty"`
}

type MasqueradedToken struct {
	Token        string    `json:"token,omitempty" doc:"Opaque token that a trusted service can exchange via /v1/unmask for the real tokens"`
	TokenExpires time.Time `json:"token_expires" doc:"Expiration time of the masquerade token: the latest expiry of the underlying tokens"`
}

type ErrorType string

const (
	AuthErrorType            ErrorType = "auth"
	BadDataErrorType         ErrorType = "bad_data"
	InternalErrorType        ErrorType = "internal"
	TooManyRequestsErrorType ErrorType = "too_many_requests"
)

type GenericError interface {
	Error() string
	PrivateError() string
	Code() int
	Type() ErrorType
}

type genericError struct {
	privateMessage string
	message        string
	errorType      ErrorType
	code           int
	originalError  error
}

func (g *genericError) Error() string {
	return g.message
}

func (g *genericError) PrivateError() string {
	if g.originalError != nil {
		if ge, ok := errors.AsType[GenericError](g.originalError); ok {
			return g.privateMessage + "; " + g.originalError.Error() + "; " + ge.PrivateError()
		}

		return g.privateMessage + "; " + g.originalError.Error()
	}
	return g.privateMessage
}

func (g *genericError) Code() int {
	return g.code
}

func (g *genericError) Type() ErrorType {
	return g.errorType
}

func NewGenericError(privateMessage, message string, errorType ErrorType, code int, originalError error) GenericError {
	return &genericError{
		privateMessage: privateMessage,
		message:        message,
		errorType:      errorType,
		code:           code,
		originalError:  originalError,
	}
}

func NewInternalError(privateMessage string, originalError error) GenericError {
	return NewGenericError(privateMessage, "internal error", InternalErrorType, 100, originalError)
}

func NewGenericAuthError(privateMessage string, publicMessage string, originalError error) GenericError {
	return NewGenericError(privateMessage, publicMessage, AuthErrorType, 1000, originalError)
}

func NewAuthError(privateMessage string, publicMessage string, code int, originalError error) GenericError {
	return NewGenericError(privateMessage, publicMessage, AuthErrorType, code, originalError)
}

func NewGenericBadRequestError(privateMessage string, publicMessage string, originalError error) GenericError {
	return NewGenericError(privateMessage, publicMessage, BadDataErrorType, 2000, originalError)
}

func NewBadRequestError(privateMessage string, publicMessage string, code int, originalError error) GenericError {
	return NewGenericError(privateMessage, publicMessage, BadDataErrorType, code, originalError)
}

func WrapWithInternalError(err error) GenericError {
	return NewInternalError(err.Error(), err)
}

var GenericUnauthorizedError = NewGenericAuthError("unauthorized", "unauthorized", nil)
var GenericInvalidUserOrPasswordError = NewGenericAuthError("invalid user or password", "invalid user or password", nil)
var GenericInvalidVerificationCodeError = NewAuthError("session expired or does not exist", "session expired or does not exist", DefaultAuthErrorCode, nil)
var GenericLoginSessionExpiredOrDoesNotExistError = NewAuthError("invalid login session", "invalid login session", DefaultAuthErrorCode, nil)
var GenericInvalidMFACodeError = NewAuthError("invalid verification code", "invalid verification code", DefaultAuthErrorCode, nil)
var GenericNoRefreshTokenError = NewGenericAuthError("unable to refresh tokens - no refresh token", "unauthorized", nil)

var GenericNoClaimsError = NewGenericAuthError("unable to extract token claims", "invalid token", nil)
var GenericNoClientIdError = NewGenericAuthError("auth token has no client ID", "invalid token", nil)
var GenericInvalidClientIdError = NewGenericAuthError("auth token has invalid client ID", "invalid token", nil)
var GenericInvalidTokenUseError = NewGenericAuthError("token has unexpected token_use", "invalid token", nil)
var GenericNoIssuerError = NewGenericAuthError("auth token has no issuer", "invalid token", nil)
var GenericInvalidIssuerError = NewGenericAuthError("auth token has invalid issuer", "invalid token", nil)

var GenericInvalidNewPasswordError = NewBadRequestError("invalid new password", "invalid new password", DefaultBadRequestCode, nil)
var GenericPasswordHistoryError = NewBadRequestError("invalid new password", "invalid new password", DefaultBadRequestCode, nil)
var GenericInvalidTokenMaskError = NewBadRequestError("invalid token mask", "invalid token", DefaultBadRequestCode, nil)
var GenericMissingLoginSessionIdError = NewBadRequestError("missing login session id", "missing login session id", DefaultBadRequestCode, nil)
var GenericMissingUpdateSessionIdError = NewBadRequestError("missing update session id", "missing update session id", DefaultBadRequestCode, nil)
var GenericUpdateSessionExpiredOrDoesNotExistError = NewAuthError("invalid update session", "invalid update session", DefaultAuthErrorCode, nil)
var GenericMissingCSRFTokenError = NewBadRequestError("missing CSRF token", "missing CSRF token", DefaultBadRequestCode, nil)
var GenericInvalidCSRFTokenError = NewBadRequestError("invalid CSRF token", "invalid CSRF token", DefaultBadRequestCode, nil)
var GenericNoTokensProvidedError = NewBadRequestError("no tokens provided", "no tokens provided", DefaultBadRequestCode, nil)
var GenericNoRefreshTokenProvidedError = NewBadRequestError("no refresh token provided", "no refresh token provided", DefaultBadRequestCode, nil)
var GenericNoUserProvidedError = NewBadRequestError("no user provided", "no user provided", DefaultBadRequestCode, nil)
var GenericNoIdTokenProvidedError = NewBadRequestError("no id token provided", "no id token provided", DefaultBadRequestCode, nil)
var GenericInvalidEmailError = NewBadRequestError("invalid email address", "invalid email address", DefaultBadRequestCode, nil)
var GenericUnsupportedMFAType = NewBadRequestError("unsupported MFA type", "unsupported MFA type", DefaultBadRequestCode, nil)
