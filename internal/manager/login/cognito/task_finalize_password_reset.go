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

type finalizePasswordResetTaskResult struct {
	withResultBase
	withPayload
}

type finalizePasswordResetTaskResultChan chan *finalizePasswordResetTaskResult

type finalizePasswordResetTask struct {
	Token    string
	Code     string
	Password string
	Task[finalizePasswordResetTaskResult, *finalizePasswordResetTaskResult]
}

func (t finalizePasswordResetTask) Process(c *Cognito) {
	t.ResultChan <- c.processFinalizePasswordResetTask(t)
}

func (c *Cognito) createFinalizePasswordResetTask(ctx context.Context, token string, code string, password string) (finalizePasswordResetTaskResultChan, loginTypes.GenericError) {
	resultChan := make(finalizePasswordResetTaskResultChan)
	err := c.appendFinalizePasswordResetTask(finalizePasswordResetTask{token, code, password, Task[finalizePasswordResetTaskResult, *finalizePasswordResetTaskResult]{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

func (c *Cognito) processFinalizePasswordResetTask(task finalizePasswordResetTask) *finalizePasswordResetTaskResult {
	ef := genericTaskErrorFactory[finalizePasswordResetTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(c.processingLogLevel, "processing")

	session, err := c.sessionStorage.GetConfirmPasswordResetSession(task.Context, task.Token)
	if err != nil {
		requestLogger.Error("failed to retrieve confirm password reset session", zap.Error(err))
		//hide any actual errors from user
		return ef(loginTypes.GenericInvalidVerificationCodeError)
	}

	requestLogger.Log(c.processingLogLevel, "resetting password", zap.String("user", session.User))

	input := &cognitoidentityprovider.ConfirmForgotPasswordInput{
		ClientId:         aws.String(c.cfg.Client.ID),
		Username:         aws.String(session.User),
		ConfirmationCode: aws.String(task.Code),
		Password:         aws.String(task.Password),
	}

	if c.cfg.Client.Secret != "" {
		input.SecretHash = aws.String(computeSecretHash(c.cfg.Client.Secret, session.User, c.cfg.Client.ID))
	}

	_, err = c.cognitoClient.ConfirmForgotPassword(task.Context, input)

	if err != nil {
		if _, ok := errors.AsType[*cognitoTypes.CodeMismatchException](err); ok {
			return ef(loginTypes.GenericInvalidVerificationCodeError)
		}

		return ef(loginTypes.NewInternalError("unable to finalize password reset", err))
	}

	requestLogger.Info("user finalized password reset",
		zap.String("user", session.User),
	)

	err = c.sessionStorage.DropConfirmPasswordResetSession(context.Background(), task.Token)
	if err != nil {
		//no point returning an error here - actual reset is complete
		requestLogger.Error("failed to drop confirm-password-reset session", zap.Error(err))
	}

	return &finalizePasswordResetTaskResult{}
}
