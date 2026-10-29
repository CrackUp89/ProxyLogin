package cognito

import (
	"context"
	loginTypes "proxylogin/internal/manager/login/types"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

type refreshTokenTaskResult struct {
	withResultBase
	withAuthResults
}

type refreshTokenTaskResultChan chan *refreshTokenTaskResult

type refreshTokenTask struct {
	User         string
	IdToken      string
	RefreshToken string
	Remember     bool
	Task[refreshTokenTaskResult, *refreshTokenTaskResult]
}

func (t refreshTokenTask) Process(c *Cognito) {
	t.ResultChan <- c.processRefreshTokenTask(t)
}

func (c *Cognito) createRefreshTokenTask(ctx context.Context, user, idToken, refreshToken string, remember bool) (refreshTokenTaskResultChan, loginTypes.GenericError) {
	resultChan := make(refreshTokenTaskResultChan)
	err := c.appendRefreshTokenTask(refreshTokenTask{User: user,
		IdToken:      idToken,
		RefreshToken: refreshToken,
		Remember:     remember,
		Context:      ctx,
		ResultChan:   resultChan,
	})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

func (c *Cognito) processRefreshTokenTask(task refreshTokenTask) *refreshTokenTaskResult {
	efp := func(err loginTypes.GenericError, logout bool) *refreshTokenTaskResult {
		r := &refreshTokenTaskResult{
			Err: err,
		}
		if logout {
			r.AddSideEffect(SideEffectOutput{Type: LogOutSideEffect})
		}
		return r
	}

	ef := func(err loginTypes.GenericError) *refreshTokenTaskResult {
		return efp(err, false)
	}

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(c.processingLogLevel, "processing", zap.String("username", task.User))

	if task.RefreshToken == "" {
		return efp(loginTypes.GenericNoRefreshTokenProvidedError, false)
	}

	// the ID token (possibly expired) tells which user and app client the refresh token belongs to
	var idTokenClaims jwt.MapClaims
	if task.IdToken != "" {
		t, err := c.jwksValidator.ParseToken(task.IdToken)
		if err != nil {
			// usually just expired; the claims are only used to address the refresh request, Cognito validates the refresh token itself
			requestLogger.Warn("id token is invalid, but will be used as a source of user name and client only", zap.Error(err))
			t, _, err = jwt.NewParser().ParseUnverified(task.IdToken, jwt.MapClaims{})
		}
		if err == nil && t != nil {
			idTokenClaims, _ = t.Claims.(jwt.MapClaims)
		} else if task.User == "" {
			return efp(loginTypes.NewGenericAuthError("unable to parse id token", "invalid token", err), false)
		}
	}

	user := task.User
	if user == "" {
		if un, ok := idTokenClaims["username"].(string); ok {
			user = un
		}
	}

	if user == "" {
		return efp(loginTypes.GenericNoUserProvidedError, true)
	}

	var clientId string
	if aud, err := idTokenClaims.GetAudience(); err == nil && len(aud) > 0 {
		clientId = aud[0]
	}
	client := c.clientConfig(clientId)

	authResult, err := c.refreshToken(task.Context, client, task.RefreshToken, user)

	if err != nil {
		return efp(loginTypes.GenericNoRefreshTokenProvidedError, true)
	}

	if authResult != nil {
		authResults := authenticationResultFromCognitoType(authResult)
		authResults.ClientID = client.ID
		if r := handleFinalAuthResults(c, task.Task.Context, authResults,
			task.User, task.Remember,
			genericAuthResultFactory[refreshTokenTaskResult], genericAuthErrorFactory[refreshTokenTaskResult]); r != nil {
			return r
		}
	}

	return efp(InconclusiveResponseError, false)
}
