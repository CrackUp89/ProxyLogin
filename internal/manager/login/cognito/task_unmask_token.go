package cognito

import (
	"context"
	"proxylogin/internal/manager/login/types"
)

type unmaskTokenTaskResult struct {
	withResultBase
	tokenSet *types.AuthTokenSet
}

type unmaskTokenTaskResultChan chan *unmaskTokenTaskResult

type unmaskTokenTask struct {
	Token string
	Task[unmaskTokenTaskResult, *unmaskTokenTaskResult]
}

func (t unmaskTokenTask) Process(c *Cognito) {
	t.ResultChan <- c.processUnmaskTokenTask(t)
}

func (c *Cognito) createUnmaskTokenTask(ctx context.Context, token string) (unmaskTokenTaskResultChan, types.GenericError) {
	resultChan := make(unmaskTokenTaskResultChan)
	err := c.appendUnmaskTokenTask(unmaskTokenTask{token, Task[unmaskTokenTaskResult, *unmaskTokenTaskResult]{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

func (c *Cognito) processUnmaskTokenTask(task unmaskTokenTask) *unmaskTokenTaskResult {
	if r := checkTaskContext(task.Task, genericTaskErrorFactory[unmaskTokenTaskResult]); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)
	requestLogger.Log(c.processingLogLevel, "processing")

	r, err := c.unmaskToken(task.Context, task.Token, requestLogger, true, c.masq.UnmaskRefreshToken())

	if err != nil {
		return genericTaskErrorFactory[unmaskTokenTaskResult](err)
	}

	return &unmaskTokenTaskResult{
		tokenSet: r,
	}
}
