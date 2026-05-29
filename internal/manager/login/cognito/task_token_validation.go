package cognito

import (
	"context"
	"proxylogin/internal/manager/login/types"
)

type tokenValidationTaskResult struct {
	withResultBase
	Validity         map[string]bool
	ValidationErrors map[string]string
}

type tokenValidationTaskResultChan chan *tokenValidationTaskResult

type tokenValidationTask struct {
	Tokens map[string]string
	Task[tokenValidationTaskResult, *tokenValidationTaskResult]
}

func (t tokenValidationTask) Process(c *Cognito) {
	t.ResultChan <- c.processValidateTask(t)
}

func (c *Cognito) createTokenValidationTask(ctx context.Context, tokens map[string]string) (tokenValidationTaskResultChan, types.GenericError) {
	resultChan := make(tokenValidationTaskResultChan)
	err := c.appendTokenValidationTask(tokenValidationTask{
		tokens,
		Task[tokenValidationTaskResult, *tokenValidationTaskResult]{ctx, resultChan},
	})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

func (c *Cognito) processValidateTask(task tokenValidationTask) *tokenValidationTaskResult {
	ef := genericTaskErrorFactory[tokenValidationTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(c.processingLogLevel, "processing")

	validity := map[string]bool{}
	validationError := map[string]string{}

	for tokenName, token := range task.Tokens {
		_, err := c.jwksValidator.ValidateToken(token)
		if err == nil {
			validity[tokenName] = true
		} else {
			validity[tokenName] = false
			validationError[tokenName] = err.Error()
		}
	}

	return &tokenValidationTaskResult{
		Validity:         validity,
		ValidationErrors: validationError,
	}
}
