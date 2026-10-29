package cognito

import (
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/url"
	"proxylogin/internal/manager/login/types"
	"strings"
	"time"

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

var httpClient = &http.Client{Timeout: 60 * time.Second}

func (c *Cognito) processExternalLoginTask(task externalLoginTask) *loginStepResult {
	ef := genericTaskErrorFactory[loginStepResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	loginSessionId := task.LoginSessionId

	unlockSession, lockErr := c.lockSession(task.Context, loginSessionId)
	if lockErr != nil {
		return ef(lockErr)
	}
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
	if c.cfg.ExternalClient.Secret == "" {
		form.Set("client_id", c.cfg.ExternalClient.ID)
	}

	req, _ := http.NewRequestWithContext(task.Context, http.MethodPost,
		c.cfg.TokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.cfg.ExternalClient.Secret != "" {
		req.SetBasicAuth(c.cfg.ExternalClient.ID, c.cfg.ExternalClient.Secret)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return ef(types.NewInternalError("code exchange request failed", err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ef(types.NewInternalError("unable to read code exchange response body", err))
	}

	if resp.StatusCode != http.StatusOK {
		requestLogger.Error("error processing external login session", zap.Int("statusCode", resp.StatusCode), zap.ByteString("body", body))
		return ef(types.NewInternalError("unexpected status code", nil))
	}

	type respBodyStr struct {
		AccessToken  *string `json:"access_token,omitempty"`
		IdToken      *string `json:"id_token,omitempty"`
		RefreshToken *string `json:"refresh_token,omitempty"`
		ExpiresIn    *int    `json:"expires_in,omitempty"`
	}

	respBody := &respBodyStr{}
	if err := json.Unmarshal(body, respBody); err != nil {
		return ef(types.NewInternalError("unable to parse response body", err))
	}

	if respBody.AccessToken == nil || *respBody.AccessToken == "" {
		return ef(types.NewInternalError("no access token found in response body", nil))
	}

	if respBody.IdToken == nil || *respBody.IdToken == "" {
		return ef(types.NewInternalError("no id token found in response body", nil))
	}

	t, err := c.jwksValidator.ParseToken(*respBody.IdToken)
	if err != nil {
		return ef(types.NewInternalError("unable to extract user from id token", err))
	}

	// the Cognito user name addresses the user in later requests (e.g. the refresh SECRET_HASH); sub is a fallback
	var user string
	for _, claim := range []string{"cognito:username", "sub"} {
		if v, ok := extractClaim(t, claim); ok {
			if s, ok := v.(string); ok && s != "" {
				user = s
				break
			}
		}
	}

	authResults := &AuthenticationResult{
		AccessToken:  respBody.AccessToken,
		IdToken:      respBody.IdToken,
		RefreshToken: respBody.RefreshToken,
		ClientID:     c.cfg.ExternalClient.ID,
	}

	return handleAuthResults(c, task.Context, authResults, user, task.RememberUser, task.CSRFToken, loginSessionId,
		c.cfg.EnforceMFAForExternalLogin,
		genericAuthResultFactory[loginStepResult], genericNextStepFactory[loginStepResult], genericAuthErrorFactory[loginStepResult],
		requestLogger)
}
