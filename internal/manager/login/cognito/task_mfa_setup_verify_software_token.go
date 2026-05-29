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

type mfaSetupVerifySoftwareTokenTaskResult loginStepResult

type mfaSetupVerifySoftwareTokenTaskResultChan chan *mfaSetupVerifySoftwareTokenTaskResult

type mfaSetupVerifySoftwareTokenTask struct {
	User string
	Code string
	withLoginSession
	withCSRFToken
	Task[mfaSetupVerifySoftwareTokenTaskResult, *mfaSetupVerifySoftwareTokenTaskResult]
}

func (t mfaSetupVerifySoftwareTokenTask) Process(c *Cognito) {
	t.ResultChan <- c.processMFASetupVerifySoftwareTokenTask(t)
}

func (c *Cognito) createMFASetupVerifySoftwareTokenTask(ctx context.Context, loginSessionId string, user string, code string, csrfToken string) (mfaSetupVerifySoftwareTokenTaskResultChan, loginTypes.GenericError) {
	resultChan := make(mfaSetupVerifySoftwareTokenTaskResultChan)
	err := c.appendMFASetupVerifySoftwareTokenTask(mfaSetupVerifySoftwareTokenTask{
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

func (c *Cognito) processMFASetupVerifySoftwareTokenTask(task mfaSetupVerifySoftwareTokenTask) *mfaSetupVerifySoftwareTokenTaskResult {
	ef := genericTaskErrorFactory[mfaSetupVerifySoftwareTokenTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	unlockSession := c.lockLoginSession(task.LoginSessionId)
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

	if r := checkNextStep(session, ef, NextStepMFASoftwareTokenSetupVerify); r != nil {
		return r
	}

	verifyInput := &cognitoidentityprovider.VerifySoftwareTokenInput{
		UserCode: aws.String(task.Code),
		//FriendlyDeviceName: aws.String("MyDevice"), // Optional device name
	}

	var mfaSession *MFAEnforcementSession
	if session.NextStepVariant == NextStepVariantMFAEnforcement {
		if s, r := getMFAEnforcementSession(c, task.Context, task.LoginSessionId, ef); r == nil {
			mfaSession = s
		} else {
			return r
		}
		verifyInput.AccessToken = mfaSession.AuthenticationResult.AccessToken
	} else {
		verifyInput.Session = aws.String(session.CognitoSession)
	}

	verifyResult, err := c.cognitoClient.VerifySoftwareToken(task.Context, verifyInput)
	if err != nil {
		if _, ok := errors.AsType[*cognitoTypes.EnableSoftwareTokenMFAException](err); ok {
			return ef(loginTypes.GenericInvalidMFACodeError)
		}
		return ef(loginTypes.WrapWithInternalError(err))
	}

	if verifyResult.Status != cognitoTypes.VerifySoftwareTokenResponseTypeSuccess {
		return ef(InconclusiveResponseError)
	}

	nsf := genericNextStepFactory[mfaSetupVerifySoftwareTokenTaskResult]

	if mfaSession != nil {
		if err := c.ensureMFAAfterUpdate(task.Context, *mfaSession.AuthenticationResult.AccessToken); err != nil {
			return ef(loginTypes.NewInternalError("failed to enable software token MFA", err))
		}

		if r := handleFinalAuthResults(c, task.Task.Context, mfaSession.AuthenticationResult,
			task.User, session.RememberUser,
			genericAuthResultFactory[mfaSetupVerifySoftwareTokenTaskResult], genericAuthErrorFactory[mfaSetupVerifySoftwareTokenTaskResult]); r != nil {
			return r
		}

		if err := c.dropMFAEnforcementSession(task.Context, task.LoginSessionId); err != nil {
			requestLogger.Error("failed to drop MFA enforcement session", zap.Error(err))
		}

		return ef(loginTypes.NewInternalError("no auth response", nil))
	}

	challengeInput := &cognitoidentityprovider.RespondToAuthChallengeInput{
		ChallengeName: cognitoTypes.ChallengeNameTypeMfaSetup,
		ClientId:      aws.String(c.cfg.Client.ID),
		Session:       verifyResult.Session,
		ChallengeResponses: map[string]string{
			"USERNAME": task.User,
		},
	}

	if c.cfg.Client.Secret != "" {
		challengeInput.ChallengeResponses["SECRET_HASH"] = computeSecretHash(c.cfg.Client.Secret, task.User, c.cfg.Client.ID)
	}

	finalResult, err := c.cognitoClient.RespondToAuthChallenge(task.Context, challengeInput)
	if err != nil {
		return ef(loginTypes.WrapWithInternalError(err))
	}

	if finalResult.AuthenticationResult != nil {
		if r := handleAuthResults(c, task.Task.Context, authenticationResultFromCognitoType(finalResult.AuthenticationResult),
			task.User, session.RememberUser, task.CSRFToken, task.LoginSessionId,
			genericAuthResultFactory[mfaSetupVerifySoftwareTokenTaskResult], nsf, genericAuthErrorFactory[mfaSetupVerifySoftwareTokenTaskResult], requestLogger); r != nil {
			return r
		}
	}

	return handleChallenge(c, finalResult.ChallengeName, finalResult.ChallengeParameters, task.Task.Context, *finalResult.Session, task.CSRFToken, task.LoginSessionId, session.RememberUser,
		nsf, ef)
}
