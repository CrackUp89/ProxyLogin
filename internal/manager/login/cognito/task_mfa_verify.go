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

type mfaVerifyTaskResult loginStepResult

type mfaVerifyTaskResultChan chan *mfaVerifyTaskResult

type mfaVerifyTask struct {
	User string
	Code string
	withLoginSession
	withCSRFToken
	Task[mfaVerifyTaskResult, *mfaVerifyTaskResult]
}

func (t mfaVerifyTask) Process(c *Cognito) {
	t.ResultChan <- c.processMFAVerifyTask(t)
}

func (c *Cognito) createMFAVerifyTask(ctx context.Context, loginSessionId string, user string, code string, csrfToken string) (mfaVerifyTaskResultChan, loginTypes.GenericError) {
	resultChan := make(mfaVerifyTaskResultChan)
	err := c.appendMFAVerifyTask(mfaVerifyTask{
		LoginSessionId: loginSessionId,
		CSRFToken:      csrfToken,
		User:           user,
		Code:           code,
		Context:        ctx,
		ResultChan:     resultChan,
	})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

func (c *Cognito) processMFAVerifyTask(task mfaVerifyTask) *mfaVerifyTaskResult {
	ef := genericTaskErrorFactory[mfaVerifyTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	unlockSession := c.lockSession(task.LoginSessionId)
	defer unlockSession()

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	var session *LoginSession
	if s, r := getLoginSession(c, task.Task.Context, task.LoginSessionId, ef); r == nil {
		session = s
	} else {
		return r
	}

	if !c.csrf.VerifyCSRFToken(task.CSRFToken, session.CSRFToken) {
		return ef(loginTypes.GenericInvalidCSRFTokenError)
	}

	requestLogger.Log(c.processingLogLevel, "processing", zap.String("loginSessionId", task.LoginSessionId), zap.String("username", task.User), zap.String("nextStep", string(session.NextStep)))

	switch session.NextStep {
	case NextStepMFASoftwareTokenVerify:
		fallthrough
	case NextStepMFAEMailVerify:
		fallthrough
	case NextStepMFASMSVerify:
		return c.verifyMFACode(session, task, session.NextStep)
	}

	return ef(NewNextStepError([]NextStep{NextStepMFASoftwareTokenVerify, NextStepMFAEMailVerify, NextStepMFASMSVerify}, session.NextStep)) //todo: maybe use checkNextSteps
}

func (c *Cognito) verifyMFACode(session *LoginSession, task mfaVerifyTask, step NextStep) *mfaVerifyTaskResult {
	ef := genericTaskErrorFactory[mfaVerifyTaskResult]

	requestLogger := getRequestLoggerFromTask(task.Task)

	challengeResp := &cognitoidentityprovider.RespondToAuthChallengeInput{
		ClientId: aws.String(c.cfg.Client.ID),
		Session:  aws.String(session.CognitoSession),
		ChallengeResponses: map[string]string{
			"USERNAME": task.User,
		},
	}

	if c.cfg.Client.Secret != "" {
		challengeResp.ChallengeResponses["SECRET_HASH"] = computeSecretHash(c.cfg.Client.Secret, task.User, c.cfg.Client.ID)
	}

	switch step {
	case NextStepMFASoftwareTokenVerify:
		challengeResp.ChallengeName = cognitoTypes.ChallengeNameTypeSoftwareTokenMfa
		challengeResp.ChallengeResponses["SOFTWARE_TOKEN_MFA_CODE"] = task.Code
		break
	case NextStepMFAEMailVerify:
		challengeResp.ChallengeName = cognitoTypes.ChallengeNameTypeEmailOtp
		challengeResp.ChallengeResponses["EMAIL_OTP_CODE"] = task.Code
		break
	case NextStepMFASMSVerify:
		challengeResp.ChallengeName = cognitoTypes.ChallengeNameTypeSmsMfa
		challengeResp.ChallengeResponses["SMS_OTP_CODE"] = task.Code
		break
	}

	result, err := c.cognitoClient.RespondToAuthChallenge(task.Context, challengeResp)
	if err != nil {
		if gErr := mapCodeVerificationError(err); gErr != nil {
			return ef(gErr)
		}
		if _, ok := errors.AsType[*cognitoTypes.NotAuthorizedException](err); ok {
			return ef(loginTypes.GenericUnauthorizedError)
		}
		return ef(loginTypes.WrapWithInternalError(err))
	}

	nsf := genericNextStepFactory[mfaVerifyTaskResult]

	if result.ChallengeName == "" {
		if result.AuthenticationResult != nil {
			if r := handleAuthResults(c, task.Task.Context, authenticationResultFromCognitoType(result.AuthenticationResult),
				task.User, session.RememberUser, task.CSRFToken, task.LoginSessionId,
				genericAuthResultFactory[mfaVerifyTaskResult], nsf, genericAuthErrorFactory[mfaVerifyTaskResult], requestLogger); r != nil {
				return r
			}
		}
		return ef(NoChallengeOrAuthenticationResultError)
	}

	return handleChallenge(c, result.ChallengeName, result.ChallengeParameters, task.Task.Context, *result.Session, task.CSRFToken, task.LoginSessionId, session.RememberUser,
		nsf, ef)
}
