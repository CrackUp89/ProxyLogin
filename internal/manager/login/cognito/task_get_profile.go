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

	tokenSet, r := checkAuth(c, task.Context, task.Auth, ef)
	if r != nil {
		return r
	}

	// a masquerade token resolves to the full token set; otherwise the ID token comes from its cookie
	idToken := tokenSet.IdToken
	if idToken == "" {
		idToken = task.IdToken
	}
	if idToken == "" {
		return ef(loginTypes.GenericNoIdTokenProvidedError)
	}

	subject, gErr := c.accessTokenSubject(tokenSet.AccessToken)
	if gErr != nil {
		return ef(gErr)
	}

	t, jwksErr := c.cognitoIdTokenToProfile(idToken, subject)
	if jwksErr != nil {
		return ef(loginTypes.NewGenericAuthError("invalid id token", "invalid token", jwksErr))
	}

	return &getProfileTaskResult{
		Profile: t,
	}
}

// cognitoIdTokenToProfile validates an ID token, checks that it belongs to subject and decodes the profile from it.
func (c *Cognito) cognitoIdTokenToProfile(token, subject string) (*UserIdTokenProfile, error) {
	t, err := c.jwksValidator.ValidateToken(token)
	if err != nil {
		return nil, err
	}

	claimsMap, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token")
	}

	if sub, _ := claimsMap["sub"].(string); sub != subject {
		return nil, errors.New("id token does not belong to the authenticated user")
	}

	groups := []string{}

	if g, ok := claimsMap["cognito:groups"].([]any); ok {
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
