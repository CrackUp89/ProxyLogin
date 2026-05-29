package cognito

import (
	"context"
	"proxylogin/internal/manager/login/types"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"go.uber.org/zap"
)

type logOutTaskResult struct {
	withResultBase
	withPayload
}

type logOutTaskResultChan chan *logOutTaskResult

type logOutTask struct {
	Token string
	Task[logOutTaskResult, *logOutTaskResult]
}

func (t logOutTask) Process(c *Cognito) {
	t.ResultChan <- c.processLogOutTask(t)
}

func (c *Cognito) createLogOutTask(ctx context.Context, token string) (logOutTaskResultChan, types.GenericError) {
	resultChan := make(logOutTaskResultChan)
	err := c.appendLogOutTask(logOutTask{token, Task[logOutTaskResult, *logOutTaskResult]{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

func (c *Cognito) processLogOutTask(task logOutTask) *logOutTaskResult {
	ef := genericTaskErrorFactory[logOutTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(c.processingLogLevel, "processing")

	//always report success
	go func() {
		ctx := context.WithoutCancel(context.Background())
		var refreshToken string

		if c.appConfig.Masquerade {
			r, err := c.unmaskToken(ctx, task.Token, requestLogger, false, true)
			if err != nil {
				requestLogger.Warn("failed to unmask token to rewoke", zap.Error(err))
				return
			}
			c.dropMasqueradedToken(task.Token, requestLogger)
			refreshToken = r.RefreshToken
		} else {
			refreshToken = task.Token
		}

		input := &cognitoidentityprovider.RevokeTokenInput{
			ClientId: aws.String(c.cfg.Client.ID),
			Token:    aws.String(refreshToken),
		}

		if c.cfg.Client.Secret != "" {
			input.ClientSecret = aws.String(c.cfg.Client.Secret)
		}

		_, err := c.cognitoClient.RevokeToken(ctx, input)

		if err != nil {
			requestLogger.Warn("failed to revoke token", zap.Error(err))
		}
	}()

	r := &logOutTaskResult{}
	r.AddSideEffect(SideEffectOutput{Type: LogOutSideEffect})

	return r
}
