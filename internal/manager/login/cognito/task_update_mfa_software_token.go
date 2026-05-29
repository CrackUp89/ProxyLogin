package cognito

import (
	"context"
	loginTypes "proxylogin/internal/manager/login/types"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

type updateMFASoftwareTokenTaskResultPayload struct {
	Code *string `json:"code"`
}

type updateMFASoftwareTokenTaskResult struct {
	withResultBase
	payload *updateMFASoftwareTokenTaskResultPayload
}

func (u *updateMFASoftwareTokenTaskResult) GetPayload() interface{} {
	return u.payload
}

func (u *updateMFASoftwareTokenTaskResult) SetPayload(_ interface{}) {
	panic("should not be called")
}

type updateMFASoftwareTokenTaskResultChan chan *updateMFASoftwareTokenTaskResult

type updateMFASoftwareTokenTask struct {
	withAuth
	Task[updateMFASoftwareTokenTaskResult, *updateMFASoftwareTokenTaskResult]
}

func (t updateMFASoftwareTokenTask) Process(c *Cognito) {
	t.ResultChan <- c.processUpdateMFASoftwareTokenTask(t)
}

func (c *Cognito) createUpdateMFASoftwareTokenTask(ctx context.Context, auth any) (updateMFASoftwareTokenTaskResultChan, loginTypes.GenericError) {
	resultChan := make(updateMFASoftwareTokenTaskResultChan)
	err := c.appendUpdateMFASoftwareTokenTask(updateMFASoftwareTokenTask{
		Auth:       auth,
		Context:    ctx,
		ResultChan: resultChan,
	})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

func (c *Cognito) processUpdateMFASoftwareTokenTask(task updateMFASoftwareTokenTask) *updateMFASoftwareTokenTaskResult {
	ef := genericTaskErrorFactory[updateMFASoftwareTokenTaskResult]

	tokenSet, r := checkAuth(c, task.Task.Context, task.Auth, ef)
	if r != nil {
		return r
	}

	associateInput := &cognitoidentityprovider.AssociateSoftwareTokenInput{
		AccessToken: aws.String(tokenSet.AccessToken),
	}

	associateResult, err := c.cognitoClient.AssociateSoftwareToken(task.Context, associateInput)
	if err != nil {
		return ef(loginTypes.WrapWithInternalError(err))
	}

	return &updateMFASoftwareTokenTaskResult{
		payload: &updateMFASoftwareTokenTaskResultPayload{
			Code: associateResult.SecretCode,
		},
	}
}
