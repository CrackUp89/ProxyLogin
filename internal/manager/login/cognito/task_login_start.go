package cognito

import (
	"context"
	loginTypes "proxylogin/internal/manager/login/types"
	"time"
)

type loginStartResult struct {
	withLoginSession
	withCSRFToken
	withResultBase
}

type loginStartTaskResultChan chan *loginStartResult

type loginStartTask struct {
	Task[loginStartResult, *loginStartResult]
}

func (t loginStartTask) Process(c *Cognito) {
	t.ResultChan <- c.processLoginStartTask(t)
}

func (c *Cognito) createLoginStartTask(ctx context.Context) (loginStartTaskResultChan, loginTypes.GenericError) {
	resultChan := make(loginStartTaskResultChan)
	err := c.appendLoginStartTask(loginStartTask{
		Context:    ctx,
		ResultChan: resultChan,
	})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

func (c *Cognito) processLoginStartTask(task loginStartTask) *loginStartResult {
	ef := genericTaskErrorFactory[loginStartResult]

	requestLogger := getRequestLoggerFromTask(task.Task)
	requestLogger.Log(c.processingLogLevel, "processing")

	loginSessionId, unlockLoginSessionId, gErr := c.reserveNewLoginSessionId(task.Context)
	if gErr != nil {
		return ef(gErr)
	}

	defer unlockLoginSessionId()

	csrfToken, err := c.csrf.GenerateCSRFToken()
	if err != nil {
		return ef(loginTypes.NewInternalError("failed to create CSRF token", err))
	}

	if err := c.sessionStorage.CreateLoginSession(task.Context, csrfToken, loginSessionId, "", NextStepLogin, NextStepVariantDefault, false, time.Now().Add(c.loginSessionValidFor), nil); err != nil {
		return ef(loginTypes.NewInternalError("failed to create login session", err))
	}

	return &loginStartResult{
		LoginSessionId: loginSessionId,
		CSRFToken:      csrfToken,
	}
}
