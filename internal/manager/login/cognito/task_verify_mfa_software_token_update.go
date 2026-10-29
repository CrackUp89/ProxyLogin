package cognito

import (
	"context"
	loginTypes "proxylogin/internal/manager/login/types"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitoTypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"go.uber.org/zap"
)

type verifyMFASoftwareTokenUpdateTaskResult struct {
	withResultBase
}

type verifyMFASoftwareTokenUpdateTaskResultChan chan *verifyMFASoftwareTokenUpdateTaskResult

type verifyMFASoftwareTokenUpdateTask struct {
	Code string
	withAuth
	withUpdateSession
	withCSRFToken
	Task[verifyMFASoftwareTokenUpdateTaskResult, *verifyMFASoftwareTokenUpdateTaskResult]
}

func (t verifyMFASoftwareTokenUpdateTask) Process(c *Cognito) {
	t.ResultChan <- c.processVerifyMFASoftwareTokenUpdateTask(t)
}

func (c *Cognito) createVerifyMFASoftwareTokenUpdateTask(ctx context.Context, code string, auth any, updateSessionId, csrfToken string) (verifyMFASoftwareTokenUpdateTaskResultChan, loginTypes.GenericError) {
	resultChan := make(verifyMFASoftwareTokenUpdateTaskResultChan)
	err := c.appendVerifyMFASoftwareTokenUpdateTask(verifyMFASoftwareTokenUpdateTask{
		Code:            code,
		Auth:            auth,
		UpdateSessionId: updateSessionId,
		CSRFToken:       csrfToken,
		Context:         ctx,
		ResultChan:      resultChan,
	})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

func (c *Cognito) processVerifyMFASoftwareTokenUpdateTask(task verifyMFASoftwareTokenUpdateTask) *verifyMFASoftwareTokenUpdateTaskResult {
	ef := genericTaskErrorFactory[verifyMFASoftwareTokenUpdateTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	unlockSession, lockErr := c.lockSession(task.Context, task.UpdateSessionId)
	if lockErr != nil {
		return ef(lockErr)
	}
	defer unlockSession()

	tokenSet, r := checkAuth(c, task.Task.Context, task.Auth, ef)
	if r != nil {
		return r
	}

	if _, r := checkUpdateSession(c, task.Task.Context, task.UpdateSessionId, task.CSRFToken, tokenSet.AccessToken, UpdateStepMFASoftwareTokenUpdateVerify, ef); r != nil {
		return r
	}

	input := &cognitoidentityprovider.VerifySoftwareTokenInput{
		AccessToken: aws.String(tokenSet.AccessToken),
		UserCode:    aws.String(task.Code),
		//FriendlyDeviceName: aws.String("MyDevice"), // Optional device name
	}

	result, err := c.cognitoClient.VerifySoftwareToken(task.Context, input)
	if err != nil {
		if gErr := mapCodeVerificationError(err); gErr != nil {
			return ef(gErr)
		}
		return ef(loginTypes.NewGenericAuthError("token verification error", "Authentication error", err))
	}

	if result.Status != cognitoTypes.VerifySoftwareTokenResponseTypeSuccess {
		return ef(InconclusiveResponseError)
	}

	if err := c.ensureMFAAfterUpdate(task.Context, tokenSet.AccessToken); err != nil {
		return ef(loginTypes.NewInternalError("failed to enable software token MFA", err))
	}

	if err := c.sessionStorage.DropUpdateSession(task.Context, task.UpdateSessionId); err != nil {
		getRequestLoggerFromTask(task.Task).Warn("failed to drop update session", zap.Error(err))
	}

	return &verifyMFASoftwareTokenUpdateTaskResult{}
}
