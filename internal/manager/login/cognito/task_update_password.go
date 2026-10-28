package cognito

import (
	"context"
	loginTypes "proxylogin/internal/manager/login/types"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"go.uber.org/zap"
)

type updatePasswordTaskResult struct {
	withResultBase
	withPayload
}

type updatePasswordTaskResultChan chan *updatePasswordTaskResult

type updatePasswordTask struct {
	withAuth
	withUpdateSession
	withCSRFToken
	CurrentPassword string
	NewPassword     string
	Task[updatePasswordTaskResult, *updatePasswordTaskResult]
}

func (t updatePasswordTask) Process(c *Cognito) {
	t.ResultChan <- c.processUpdatePasswordTask(t)
}

func (c *Cognito) createUpdatePasswordTask(ctx context.Context, currentPassword, newPassword string, auth any, updateSessionId, csrfToken string) (updatePasswordTaskResultChan, loginTypes.GenericError) {
	resultChan := make(updatePasswordTaskResultChan)
	err := c.appendUpdatePasswordTask(updatePasswordTask{
		Auth:            auth,
		UpdateSessionId: updateSessionId,
		CSRFToken:       csrfToken,
		CurrentPassword: currentPassword,
		NewPassword:     newPassword,
		Context:         ctx,
		ResultChan:      resultChan,
	})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

func (c *Cognito) processUpdatePasswordTask(task updatePasswordTask) *updatePasswordTaskResult {
	ef := genericTaskErrorFactory[updatePasswordTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(c.processingLogLevel, "processing")

	unlockSession := c.lockSession(task.UpdateSessionId)
	defer unlockSession()

	tokenSet, r := checkAuth(c, task.Task.Context, task.Auth, ef)
	if r != nil {
		return r
	}

	if _, r := checkUpdateSession(c, task.Task.Context, task.UpdateSessionId, task.CSRFToken, tokenSet.AccessToken, UpdateStepPasswordUpdate, ef); r != nil {
		return r
	}

	input := &cognitoidentityprovider.ChangePasswordInput{
		AccessToken:      aws.String(tokenSet.AccessToken),
		PreviousPassword: aws.String(task.CurrentPassword),
		ProposedPassword: aws.String(task.NewPassword),
	}

	_, err := c.cognitoClient.ChangePassword(task.Context, input)

	if err != nil {
		return ef(loginTypes.WrapWithInternalError(err))
	}

	if err := c.sessionStorage.DropUpdateSession(task.Context, task.UpdateSessionId); err != nil {
		getRequestLoggerFromTask(task.Task).Warn("failed to drop update session", zap.Error(err))
	}

	return &updatePasswordTaskResult{}
}
