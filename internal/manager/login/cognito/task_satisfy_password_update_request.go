package cognito

import (
	"context"
	"errors"
	loginTypes "proxylogin/internal/manager/login/types"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitoTypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"go.uber.org/zap"
)

const userAttributesPrefix = "userAttributes."

type satisfyPasswordUpdateRequestTaskResult loginStepResult

type satisfyPasswordUpdateRequestTaskResultChan chan *satisfyPasswordUpdateRequestTaskResult

type satisfyPasswordUpdateRequestTask struct {
	User       string
	Password   string
	Attributes map[string]string
	withLoginSession
	withCSRFToken
	Task[satisfyPasswordUpdateRequestTaskResult, *satisfyPasswordUpdateRequestTaskResult]
}

func (t satisfyPasswordUpdateRequestTask) Process(c *Cognito) {
	t.ResultChan <- c.processSatisfyPasswordUpdateRequestTask(t)
}

func (c *Cognito) createSatisfyPasswordUpdateRequestTask(ctx context.Context, loginSessionId string, user string, password string, attributes map[string]string, csrfToken string) (satisfyPasswordUpdateRequestTaskResultChan, loginTypes.GenericError) {
	resultChan := make(satisfyPasswordUpdateRequestTaskResultChan)
	err := c.appendSatisfyPasswordUpdateRequestTask(
		satisfyPasswordUpdateRequestTask{
			LoginSessionId: loginSessionId,
			CSRFToken:      csrfToken,
			User:           user,
			Password:       password,
			Attributes:     attributes,
			Context:        ctx,
			ResultChan:     resultChan,
		})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

func (c *Cognito) processSatisfyPasswordUpdateRequestTask(task satisfyPasswordUpdateRequestTask) *satisfyPasswordUpdateRequestTaskResult {
	ef := genericTaskErrorFactory[satisfyPasswordUpdateRequestTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	unlockSession, lockErr := c.lockSession(task.Context, task.LoginSessionId)
	if lockErr != nil {
		return ef(lockErr)
	}
	defer unlockSession()

	requestLogger.Log(c.processingLogLevel, "processing", zap.String("loginSessionId", task.LoginSessionId), zap.String("username", task.User))

	var session *LoginSession
	if s, r := getLoginSession(c, task.Task.Context, task.LoginSessionId, ef); r == nil {
		session = s
	} else {
		return r
	}

	if !c.csrf.VerifyCSRFToken(task.CSRFToken, session.CSRFToken) {
		return ef(loginTypes.GenericInvalidCSRFTokenError)
	}

	if r := checkNextStep(session, ef, NextStepNewPassword); r != nil {
		return r
	}

	input := &cognitoidentityprovider.RespondToAuthChallengeInput{
		ChallengeName: cognitoTypes.ChallengeNameTypeNewPasswordRequired,
		ClientId:      aws.String(c.cfg.Client.ID),
		Session:       aws.String(session.CognitoSession),
		ChallengeResponses: map[string]string{
			"USERNAME":     task.User,
			"NEW_PASSWORD": task.Password,
		},
	}

	//todo: source required attributes from tag
	for name, value := range task.Attributes {
		name = strings.TrimPrefix(name, userAttributesPrefix)
		if name == "" {
			continue
		}
		input.ChallengeResponses[userAttributesPrefix+name] = value
	}

	if c.cfg.Client.Secret != "" {
		input.ChallengeResponses["SECRET_HASH"] = computeSecretHash(c.cfg.Client.Secret, task.User, c.cfg.Client.ID)
	}

	result, err := c.cognitoClient.RespondToAuthChallenge(task.Context, input)
	if err != nil {
		if _, ok := errors.AsType[*cognitoTypes.PasswordHistoryPolicyViolationException](err); ok {
			return ef(loginTypes.GenericPasswordHistoryError)
		}

		if _, ok := errors.AsType[*cognitoTypes.InvalidPasswordException](err); ok {
			return ef(loginTypes.GenericInvalidNewPasswordError)
		}

		return ef(loginTypes.WrapWithInternalError(err))
	}

	nsf := genericNextStepFactory[satisfyPasswordUpdateRequestTaskResult]

	if result.ChallengeName == "" {
		if result.AuthenticationResult != nil {
			if r := handleAuthResults(c, task.Task.Context, authenticationResultFromCognitoType(result.AuthenticationResult),
				task.User, session.RememberUser, task.CSRFToken, task.LoginSessionId, c.cfg.EnforceMFA,
				genericAuthResultFactory[satisfyPasswordUpdateRequestTaskResult], nsf, genericAuthErrorFactory[satisfyPasswordUpdateRequestTaskResult], requestLogger); r != nil {
				return r
			}
		}
		return ef(NoChallengeOrAuthenticationResultError)
	}

	return handleChallenge(c, result.ChallengeName, result.ChallengeParameters, task.Task.Context, *result.Session, task.CSRFToken, task.LoginSessionId, session.RememberUser,
		genericNextStepFactory[satisfyPasswordUpdateRequestTaskResult], ef)
}
