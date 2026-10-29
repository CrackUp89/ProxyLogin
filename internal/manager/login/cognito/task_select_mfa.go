package cognito

import (
	"context"
	loginTypes "proxylogin/internal/manager/login/types"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitoTypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"go.uber.org/zap"
)

type selectMFATaskResult loginStepResult

type selectMFATaskResultChan chan *selectMFATaskResult

type selectMFATask struct {
	User    string
	MFAType loginTypes.MFAType
	withLoginSession
	withCSRFToken
	Task[selectMFATaskResult, *selectMFATaskResult]
}

func (t selectMFATask) Process(c *Cognito) {
	t.ResultChan <- c.processSelectMFATask(t)
}

func (c *Cognito) createSelectMFATask(ctx context.Context, loginSessionId string, user string, mfaType loginTypes.MFAType, csrfToken string) (selectMFATaskResultChan, loginTypes.GenericError) {
	resultChan := make(selectMFATaskResultChan)
	err := c.appendSelectMFATask(selectMFATask{
		LoginSessionId: loginSessionId,
		CSRFToken:      csrfToken,
		User:           user,
		MFAType:        mfaType,
		Context:        ctx,
		ResultChan:     resultChan,
	})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

func (c *Cognito) processSelectMFATask(task selectMFATask) *selectMFATaskResult {
	ef := genericTaskErrorFactory[selectMFATaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(c.processingLogLevel, "processing")

	unlockSession, lockErr := c.lockSession(task.Context, task.LoginSessionId)
	if lockErr != nil {
		return ef(lockErr)
	}
	defer unlockSession()

	requestLogger.Log(c.processingLogLevel, "processing", zap.String("loginSessionId", task.LoginSessionId), zap.String("mfaType", string(task.MFAType)))

	var session *LoginSession
	if s, r := getLoginSession(c, task.Task.Context, task.LoginSessionId, ef); r == nil {
		session = s
	} else {
		return r
	}

	if !c.csrf.VerifyCSRFToken(task.CSRFToken, session.CSRFToken) {
		return ef(loginTypes.GenericInvalidCSRFTokenError)
	}

	if r := checkNextStep(session, ef, NextStepMFASelect); r != nil {
		return r
	}

	t, ok := reverseMFAMapping[task.MFAType]
	if !ok {
		return ef(loginTypes.GenericUnsupportedMFAType)
	}

	input := &cognitoidentityprovider.RespondToAuthChallengeInput{
		ChallengeName: cognitoTypes.ChallengeNameTypeSelectMfaType,
		ClientId:      aws.String(c.cfg.Client.ID),
		Session:       aws.String(session.CognitoSession),
		ChallengeResponses: map[string]string{
			"ANSWER":   t,
			"USERNAME": task.User,
		},
	}

	if c.cfg.Client.Secret != "" {
		input.ChallengeResponses["SECRET_HASH"] = computeSecretHash(c.cfg.Client.Secret, task.User, c.cfg.Client.ID)
	}

	result, err := c.cognitoClient.RespondToAuthChallenge(task.Context, input)
	if err != nil {
		return ef(loginTypes.NewGenericAuthError("auth challenge response error", "Authentication error", err))
	}

	return handleChallenge(c, result.ChallengeName, result.ChallengeParameters, task.Task.Context, *result.Session, task.CSRFToken, task.LoginSessionId, session.RememberUser,
		genericNextStepFactory[selectMFATaskResult], ef)
}
