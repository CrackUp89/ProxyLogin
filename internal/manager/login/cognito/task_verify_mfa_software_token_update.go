package cognito

import (
	"context"
	"errors"
	loginTypes "proxylogin/internal/manager/login/types"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitoTypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

type verifyMFASoftwareTokenUpdateTaskResult struct {
	withResultBase
}

type verifyMFASoftwareTokenUpdateTaskResultChan chan *verifyMFASoftwareTokenUpdateTaskResult

type verifyMFASoftwareTokenUpdateTask struct {
	Code string
	withAuth
	Task[verifyMFASoftwareTokenUpdateTaskResult, *verifyMFASoftwareTokenUpdateTaskResult]
}

func (t verifyMFASoftwareTokenUpdateTask) Process(c *Cognito) {
	t.ResultChan <- c.processVerifyMFASoftwareTokenUpdateTask(t)
}

func (c *Cognito) createVerifyMFASoftwareTokenUpdateTask(ctx context.Context, code string, auth any) (verifyMFASoftwareTokenUpdateTaskResultChan, loginTypes.GenericError) {
	resultChan := make(verifyMFASoftwareTokenUpdateTaskResultChan)
	err := c.appendVerifyMFASoftwareTokenUpdateTask(verifyMFASoftwareTokenUpdateTask{
		Code:       code,
		Auth:       auth,
		Context:    ctx,
		ResultChan: resultChan,
	})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

func (c *Cognito) processVerifyMFASoftwareTokenUpdateTask(task verifyMFASoftwareTokenUpdateTask) *verifyMFASoftwareTokenUpdateTaskResult {
	ef := genericTaskErrorFactory[verifyMFASoftwareTokenUpdateTaskResult]

	tokenSet, r := checkAuth(c, task.Task.Context, task.Auth, ef)
	if r != nil {
		return r
	}

	input := &cognitoidentityprovider.VerifySoftwareTokenInput{
		AccessToken: aws.String(tokenSet.AccessToken),
		UserCode:    aws.String(task.Code),
		//FriendlyDeviceName: aws.String("MyDevice"), // Optional device name
	}

	result, err := c.cognitoClient.VerifySoftwareToken(task.Context, input)
	if err != nil {
		if _, errOk := errors.AsType[*cognitoTypes.EnableSoftwareTokenMFAException](err); errOk {
			return ef(loginTypes.GenericInvalidMFACodeError)
		}
		return ef(loginTypes.NewGenericAuthError("token verification error", "Authentication error", err))
	}

	if result.Status != cognitoTypes.VerifySoftwareTokenResponseTypeSuccess {
		return ef(InconclusiveResponseError)
	}

	if err := c.ensureMFAAfterUpdate(task.Context, tokenSet.AccessToken); err != nil {
		return ef(loginTypes.NewInternalError("failed to enable software token MFA", err))
	}

	return &verifyMFASoftwareTokenUpdateTaskResult{}
}
