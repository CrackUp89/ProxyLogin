package cognito

import (
	"context"
	loginTypes "proxylogin/internal/manager/login/types"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"go.uber.org/zap"
)

type mfaSetupTaskResult loginStepResult

type mfaSetupTaskResultChan chan *mfaSetupTaskResult

type mfaSetupTask struct {
	User    string
	MFAType loginTypes.MFAType
	withLoginSession
	withCSRFToken
	Task[mfaSetupTaskResult, *mfaSetupTaskResult]
}

func (t mfaSetupTask) Process(c *Cognito) {
	t.ResultChan <- c.processMFASetupTask(t)
}

func (c *Cognito) createMFASetupTask(ctx context.Context, loginSessionId string, user string, setupType loginTypes.MFAType, csrfToken string) (mfaSetupTaskResultChan, loginTypes.GenericError) {
	resultChan := make(mfaSetupTaskResultChan)
	err := c.appendMFASetupTask(mfaSetupTask{
		LoginSessionId: loginSessionId,
		CSRFToken:      csrfToken,
		User:           user,
		MFAType:        setupType,
		Context:        ctx,
		ResultChan:     resultChan,
	})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

func (c *Cognito) processMFASetupTask(task mfaSetupTask) *mfaSetupTaskResult {
	ef := genericTaskErrorFactory[mfaSetupTaskResult]

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

	if r := checkNextStep(session, ef, NextStepMFASetup); r != nil {
		return r
	}

	switch task.MFAType {
	case loginTypes.MFATypeSoftwareToken:

		var associateInput *cognitoidentityprovider.AssociateSoftwareTokenInput
		var nextStepVariant NextStepVariant
		var mfaSession *MFAEnforcementSession = nil

		if session.NextStepVariant == NextStepVariantMFAEnforcement {
			if s, r := getMFAEnforcementSession(c, task.Context, task.LoginSessionId, ef); r == nil {
				mfaSession = s
			} else {
				return r
			}

			associateInput = &cognitoidentityprovider.AssociateSoftwareTokenInput{
				AccessToken: mfaSession.AuthenticationResult.AccessToken,
			}
			nextStepVariant = NextStepVariantMFAEnforcement
		} else {
			associateInput = &cognitoidentityprovider.AssociateSoftwareTokenInput{
				Session: aws.String(session.CognitoSession),
			}
			nextStepVariant = NextStepVariantDefault
		}

		associateResult, err := c.cognitoClient.AssociateSoftwareToken(task.Context, associateInput)
		if err != nil {
			return ef(loginTypes.WrapWithInternalError(err))
		}

		expiration := time.Now().Add(c.loginSessionValidFor)

		cognitoSession := ""
		if associateResult.Session != nil {
			cognitoSession = *associateResult.Session
		}

		if err := c.sessionStorage.CreateLoginSession(task.Context, task.CSRFToken, task.LoginSessionId, cognitoSession, NextStepMFASoftwareTokenSetupVerify, nextStepVariant, session.RememberUser, expiration, nil); err != nil {
			return ef(loginTypes.NewInternalError("failed to create login session", err))
		}

		if mfaSession != nil {
			if err := c.sessionStorage.CreateMFAEnforcementSession(task.Context, task.LoginSessionId, mfaSession.User, session.RememberUser, mfaSession.AuthenticationResult, expiration); err != nil {
				return ef(loginTypes.NewInternalError("failed to create MFA enforcement session", err))
			}
		}

		return &mfaSetupTaskResult{
			nextLoginStep: &NextLoginStep{
				NextStep:       NextStepMFASoftwareTokenSetupVerify,
				LoginSessionId: task.LoginSessionId,
				Payload:        associateResult.SecretCode,
			},
		}
	}

	return ef(loginTypes.NewBadRequestError("unsupported MFA setup type", "unsupported MFA setup type", loginTypes.DefaultBadRequestCode, nil))
}
