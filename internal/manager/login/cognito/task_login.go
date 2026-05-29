package cognito

import (
	"context"
	"errors"
	loginTypes "proxylogin/internal/manager/login/types"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitoTypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"go.uber.org/zap"
)

type loginTaskResultChan chan *loginStepResult

type loginTask struct {
	User         string
	Password     string
	RememberUser bool
	withLoginSession
	withCSRFToken
	Task[loginStepResult, *loginStepResult]
}

func (t loginTask) Process(c *Cognito) {
	t.ResultChan <- c.processLoginTask(t)
}

func (c *Cognito) createLoginTask(ctx context.Context, loginSessionId string, user string, password string, rememberUser bool, csrfToken string) (loginTaskResultChan, loginTypes.GenericError) {
	resultChan := make(loginTaskResultChan)
	err := c.appendLoginTask(loginTask{
		LoginSessionId: loginSessionId,
		CSRFToken:      csrfToken,
		User:           user,
		Password:       password,
		RememberUser:   rememberUser,
		Context:        ctx,
		ResultChan:     resultChan})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

func (c *Cognito) processLoginTask(task loginTask) *loginStepResult {
	ef := genericTaskErrorFactory[loginStepResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	loginSessionId := task.LoginSessionId

	unlockSession := c.lockLoginSession(loginSessionId)
	defer unlockSession()

	requestLogger.Log(c.processingLogLevel, "processing", zap.String("loginSessionId", loginSessionId), zap.String("username", task.User))

	var session *LoginSession
	if s, r := getLoginSession(c, task.Task.Context, loginSessionId, ef); r == nil {
		session = s
	} else {
		return r
	}

	if !c.csrf.VerifyCSRFToken(task.CSRFToken, session.CSRFToken) {
		return ef(loginTypes.GenericInvalidCSRFTokenError)
	}

	if r := checkNextStep(session, ef, NextStepLogin); r != nil {
		return r
	}

	authInput := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: cognitoTypes.AuthFlowTypeUserPasswordAuth,
		ClientId: aws.String(c.cfg.Client.ID),
		AuthParameters: map[string]string{
			"USERNAME": task.User,
			"PASSWORD": task.Password,
		},
	}

	if c.cfg.Client.Secret != "" {
		authInput.AuthParameters["SECRET_HASH"] = computeSecretHash(c.cfg.Client.Secret, task.User, c.cfg.Client.ID)
	}

	result, err := c.cognitoClient.InitiateAuth(task.Context, authInput)

	if err != nil {
		var ip *cognitoTypes.NotAuthorizedException
		if _, ok := errors.AsType[*cognitoTypes.UserNotFoundException](err); ok || errors.As(err, &ip) {
			return ef(loginTypes.GenericInvalidUserOrPasswordError)
		}

		return ef(loginTypes.NewInternalError("unable to log in", err))
	}

	nsf := genericNextStepFactory[loginStepResult]

	err = c.dropLoginSession(task.Context, loginSessionId)
	if err != nil {
		return ef(loginTypes.NewInternalError("unable to drop login session", err))
	}

	unlockSession()

	nextLoginSessionId, unlockNextLoginSession, gErr := c.reserveNewLoginSessionId(task.Context)
	if gErr != nil {
		return ef(gErr)
	}
	defer unlockNextLoginSession()

	if result.ChallengeName == "" {
		if result.AuthenticationResult != nil {
			if r := handleAuthResults(c, task.Task.Context, authenticationResultFromCognitoType(result.AuthenticationResult),
				task.User, task.RememberUser, task.CSRFToken, nextLoginSessionId,
				genericAuthResultFactory[loginStepResult], nsf, genericAuthErrorFactory[loginStepResult], requestLogger); r != nil {
				return r
			}
		}
		return ef(NoChallengeOrAuthenticationResultError)
	}

	return handleChallenge(c, result.ChallengeName, result.ChallengeParameters,
		task.Task.Context, *result.Session, task.CSRFToken, nextLoginSessionId, task.RememberUser,
		nsf, ef)
}
