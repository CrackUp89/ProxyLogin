package cognito

import (
	"context"
	"errors"
	loginTypes "proxylogin/internal/manager/login/types"

	"github.com/golang-jwt/jwt/v5"
)

type getProfileTaskResult struct {
	withResultBase
	Profile *UserIdTokenProfile
}

func (g *getProfileTaskResult) GetPayload() any {
	return g.Profile
}

func (g *getProfileTaskResult) SetPayload(_ any) {
	panic("should not be called")
}

type getProfileTaskResultChan chan *getProfileTaskResult

type getProfileTask struct {
	IdToken string
	withAuth
	Task[getProfileTaskResult, *getProfileTaskResult]
}

func (t getProfileTask) Process(c *Cognito) {
	t.ResultChan <- c.processGetProfileTask(t)
}

func (c *Cognito) createGetProfileTask(ctx context.Context, idToken string, auth any) (getProfileTaskResultChan, loginTypes.GenericError) {
	resultChan := make(getProfileTaskResultChan)
	err := c.appendGetProfileTask(getProfileTask{
		IdToken:    idToken,
		Auth:       auth,
		Context:    ctx,
		ResultChan: resultChan,
	})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

func (c *Cognito) processGetProfileTask(task getProfileTask) *getProfileTaskResult {
	ef := genericTaskErrorFactory[getProfileTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(c.processingLogLevel, "processing")

	var idToken string
	if _, r := checkAuth(c, task.Context, task.Auth, ef); r != nil {
		return r
	}

	switch task.Auth.(type) {
	case TokenAuth:
		idToken = task.IdToken
	}

	//if task.MasqueradedToken == "" {
	//	if _, r := checkAuth(c, task.Task.Context, ef); r != nil {
	//		return r
	//	}
	//	idToken = task.IdToken
	//} else {
	//	r, err := c.unmaskToken(task.Context, task.MasqueradedToken, requestLogger, true, c.masq.UnmaskRefreshToken())
	//
	//	if err != nil {
	//		return ef(err)
	//	}
	//
	//	if r := checkAuthToken(c, r.AccessToken, ef); r != nil {
	//		return r
	//	}
	//
	//	idToken = r.IdToken
	//}

	if idToken == "" {
		return ef(loginTypes.GenericNoIdTokenProvidedError)
	}

	t, jwksErr := c.cognitoIdTokenToProfile(idToken)
	if jwksErr != nil {
		return ef(loginTypes.NewInternalError("jwks error", jwksErr))
	}

	return &getProfileTaskResult{
		Profile: t,
	}
}

func (c *Cognito) cognitoIdTokenToProfile(token string) (*UserIdTokenProfile, error) {
	t, err := c.jwksValidator.ValidateToken(token)
	if err != nil {
		return nil, err
	}

	claimsMap, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token")
	}

	var groups []string

	if g, ok := claimsMap["cognito:groups"].([]interface{}); ok {
		for _, gn := range g {
			if gn, ok := gn.(string); ok {
				groups = append(groups, gn)
			}
		}
	}

	username := "unknown"
	if u, ok := claimsMap["cognito:username"]; ok {
		username = u.(string)
	}

	email := "unknown"
	if e, ok := claimsMap["email"]; ok {
		email = e.(string)
	}

	emailVerified := false
	if v, ok := claimsMap["email_verified"]; ok {
		emailVerified = v.(bool)
	}

	r := &UserIdTokenProfile{
		Groups:        groups,
		Username:      username,
		Email:         email,
		EmailVerified: emailVerified,
	}

	return r, nil
}
