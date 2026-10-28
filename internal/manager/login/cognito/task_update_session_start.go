package cognito

import (
	"context"
	loginTypes "proxylogin/internal/manager/login/types"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

type withUpdateSession struct {
	UpdateSessionId string
}

type updateSessionStartResult struct {
	withUpdateSession
	withCSRFToken
	withResultBase
}

type updateSessionStartTaskResultChan chan *updateSessionStartResult

// updateSessionStartTask opens an update session for the authenticated user. Step is the flow's first step.
type updateSessionStartTask struct {
	Step UpdateStep
	withAuth
	Task[updateSessionStartResult, *updateSessionStartResult]
}

func (t updateSessionStartTask) Process(c *Cognito) {
	t.ResultChan <- c.processUpdateSessionStartTask(t)
}

func (c *Cognito) createUpdateSessionStartTask(ctx context.Context, step UpdateStep, auth any) (updateSessionStartTaskResultChan, loginTypes.GenericError) {
	resultChan := make(updateSessionStartTaskResultChan)
	err := c.appendUpdateSessionStartTask(updateSessionStartTask{
		Step:       step,
		Auth:       auth,
		Context:    ctx,
		ResultChan: resultChan,
	})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

func (c *Cognito) processUpdateSessionStartTask(task updateSessionStartTask) *updateSessionStartResult {
	ef := genericTaskErrorFactory[updateSessionStartResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)
	requestLogger.Log(c.processingLogLevel, "processing", zap.String("step", string(task.Step)))

	tokenSet, r := checkAuth(c, task.Task.Context, task.Auth, ef)
	if r != nil {
		return r
	}

	subject, gErr := c.accessTokenSubject(tokenSet.AccessToken)
	if gErr != nil {
		return ef(gErr)
	}

	updateSessionId, unlockUpdateSession, gErr := c.reserveNewUpdateSessionId(task.Context)
	if gErr != nil {
		return ef(gErr)
	}
	defer unlockUpdateSession()

	csrfToken, err := c.csrf.GenerateCSRFToken()
	if err != nil {
		return ef(loginTypes.NewInternalError("failed to create CSRF token", err))
	}

	if err := c.sessionStorage.CreateUpdateSession(task.Context, updateSessionId, c.newUpdateSession(csrfToken, subject, task.Step)); err != nil {
		return ef(loginTypes.NewInternalError("failed to create update session", err))
	}

	return &updateSessionStartResult{
		UpdateSessionId: updateSessionId,
		CSRFToken:       csrfToken,
	}
}

// accessTokenSubject returns the "sub" claim of an already validated access token.
func (c *Cognito) accessTokenSubject(accessToken string) (string, loginTypes.GenericError) {
	t, err := c.jwksValidator.ParseToken(accessToken)
	if err != nil {
		return "", loginTypes.NewGenericAuthError("unable to parse access token", "invalid token", err)
	}
	if claims, ok := t.Claims.(jwt.MapClaims); ok {
		if sub, ok := claims["sub"].(string); ok && sub != "" {
			return sub, nil
		}
	}
	return "", loginTypes.GenericNoClaimsError
}

// checkUpdateSession loads an update session and checks that it is at the expected step,
// belongs to the user of accessToken and matches the CSRF token sent with the request.
// The caller must hold the session lock.
func checkUpdateSession[R any, PR interface {
	*R
	WithTaskResultBase
}](c *Cognito, ctx context.Context, updateSessionId, csrfToken, accessToken string, step UpdateStep, ef errorFactory[R, PR]) (*UpdateSession, PR) {
	session, err := c.sessionStorage.GetUpdateSession(ctx, updateSessionId)
	if err != nil {
		return nil, ef(loginTypes.NewInternalError("failed to retrieve update session", err))
	}
	if session == nil {
		return nil, ef(loginTypes.GenericUpdateSessionExpiredOrDoesNotExistError)
	}

	if !c.csrf.VerifyCSRFToken(csrfToken, session.CSRFToken) {
		return nil, ef(loginTypes.GenericInvalidCSRFTokenError)
	}

	subject, gErr := c.accessTokenSubject(accessToken)
	if gErr != nil {
		return nil, ef(gErr)
	}
	if subject != session.Subject {
		return nil, ef(loginTypes.GenericUnauthorizedError)
	}

	if session.Step != step {
		return nil, ef(loginTypes.NewBadRequestError("unexpected update step: "+string(session.Step)+"; expected: "+string(step), "unexpected update step", loginTypes.DefaultBadRequestCode, nil))
	}

	return session, nil
}
