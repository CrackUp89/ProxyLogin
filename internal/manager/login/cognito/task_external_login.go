package cognito

import (
	"context"
	"net/http"
	"net/url"
	"proxylogin/internal/manager/login/types"
	"strings"

	"go.uber.org/zap"
)

type externalLoginTaskResultChan chan *loginStepResult

type externalLoginTask struct {
	Code         string
	RememberUser bool
	withLoginSession
	withCSRFToken
	Task[loginStepResult, *loginStepResult]
}

func (t externalLoginTask) Process(c *Cognito) {
	t.ResultChan <- c.processExternalLoginTask(t)
}

func (c *Cognito) createExternalLoginTask(ctx context.Context, loginSessionId string, code string, rememberUser bool, csrfToken string) (externalLoginTaskResultChan, types.GenericError) {
	resultChan := make(externalLoginTaskResultChan)
	err := c.appendExternalLoginTask(externalLoginTask{
		LoginSessionId: loginSessionId,
		CSRFToken:      csrfToken,
		Code:           code,
		RememberUser:   rememberUser,
		Context:        ctx,
		ResultChan:     resultChan,
	})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

func (c *Cognito) processExternalLoginTask(task externalLoginTask) *loginStepResult {
	ef := genericTaskErrorFactory[loginStepResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	loginSessionId := task.LoginSessionId

	unlockSession := c.lockLoginSession(loginSessionId)
	defer unlockSession()

	requestLogger.Log(c.processingLogLevel, "processing", zap.String("loginSessionId", loginSessionId))

	var session *LoginSession
	if s, r := getLoginSession(c, task.Task.Context, loginSessionId, ef); r == nil {
		session = s
	} else {
		return r
	}

	if !c.csrf.VerifyCSRFToken(task.CSRFToken, session.CSRFToken) {
		return ef(types.GenericInvalidCSRFTokenError)
	}

	if r := checkNextStep(session, ef, NextStepLogin); r != nil {
		return r
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", task.Code)
	form.Set("redirect_uri", c.cfg.ExternalLoginRedirectURL)
	if c.cfg.Client.Secret == "" {
		form.Set("client_id", c.cfg.Client.ID)
	}

	req, _ := http.NewRequestWithContext(task.Context, http.MethodPost,
		c.cfg.TokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.cfg.Client.Secret != "" {
		req.SetBasicAuth(c.cfg.Client.ID, c.cfg.Client.Secret)
	}
	panic("not implemented")
}
