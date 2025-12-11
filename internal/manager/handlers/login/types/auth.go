package types

type TokenSet struct {
	AccessToken  string `json:"access_token,omitempty"`
	IdToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type GenericError interface {
	Error() string
	PrivateError() string
	Code() int
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

func NewGenericAuthenticationError(privateMessage string, publicMessage string, originalError error) *GenericAuthenticationError {
	return &GenericAuthenticationError{privateMessage, publicMessage, originalError}
}

type SessionExpiredOrDoesNotExistError struct{}

func (s *SessionExpiredOrDoesNotExistError) Error() string {
	return "Session expired or does not exist"
}

func (s *SessionExpiredOrDoesNotExistError) PrivateError() string {
	return "Session expired or does not exist"
}

func (s *SessionExpiredOrDoesNotExistError) Code() int {
	return 1001
}

func NewSessionExpiredOrDoesNotExistError() *SessionExpiredOrDoesNotExistError {
	return &SessionExpiredOrDoesNotExistError{}
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

var InvalidUserOrPasswordError = invalidUserOrPasswordError{}
