package cognito

import (
	"fmt"
	"proxylogin/internal/manager/login/types"
	"proxylogin/internal/manager/tools"
)

type NextStepError struct {
	Expected []NextStep
	Received NextStep
}

func (e NextStepError) Code() int {
	return 1002
}

func (e NextStepError) Error() string {
	return "unexpected next step"
}

func (e NextStepError) PrivateError() string {
	return fmt.Sprintf("unexpected next step: %s; expected: %s", e.Received, tools.JoinStringable(e.Expected, ", "))
}

func (e NextStepError) Type() types.ErrorType {
	return types.BadDataErrorType
}

func NewNextStepError(expected []NextStep, received NextStep) *NextStepError {
	return &NextStepError{expected, received}
}

type noChallengeOrAuthenticationResultError struct{}

func (e noChallengeOrAuthenticationResultError) Code() int {
	return 10000
}

func (e noChallengeOrAuthenticationResultError) Error() string {
	return "internal error"
}

func (e noChallengeOrAuthenticationResultError) PrivateError() string {
	return "received no challenge requested or authentication result"
}

func (e noChallengeOrAuthenticationResultError) Type() types.ErrorType {
	return types.InternalErrorType
}

var NoChallengeOrAuthenticationResultError = noChallengeOrAuthenticationResultError{}

type inconclusiveResponseError struct{}

func (e inconclusiveResponseError) Code() int {
	return 10000
}

func (e inconclusiveResponseError) Error() string {
	return "internal error"
}

func (e inconclusiveResponseError) PrivateError() string {
	return "received no error or conclusive result"
}

func (e inconclusiveResponseError) Type() types.ErrorType {
	return types.InternalErrorType
}

var InconclusiveResponseError = inconclusiveResponseError{}
