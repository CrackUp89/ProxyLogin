package cognito

import (
	"context"
	"fmt"
	loginTypes "proxylogin/internal/manager/login/types"
	"proxylogin/internal/manager/tools"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"go.uber.org/zap"
)

type resetPasswordTaskResult struct {
	withResultBase
	redirectTo string
}

type resetPasswordTaskResultChan chan *resetPasswordTaskResult

type resetPasswordTask struct {
	Token string
	Task[resetPasswordTaskResult, *resetPasswordTaskResult]
}

func (t resetPasswordTask) Process(c *Cognito) {
	t.ResultChan <- c.processResetPasswordTask(t)
}

func (c *Cognito) createResetPasswordTask(ctx context.Context, token string) (resetPasswordTaskResultChan, loginTypes.GenericError) {
	resultChan := make(resetPasswordTaskResultChan)
	err := c.appendResetPasswordTask(resetPasswordTask{token, Task[resetPasswordTaskResult, *resetPasswordTaskResult]{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

func (c *Cognito) processResetPasswordTask(task resetPasswordTask) *resetPasswordTaskResult {
	ef := genericTaskErrorFactory[resetPasswordTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(c.processingLogLevel, "processing")

	resetSettings := c.appConfig.PasswordResetConfig

	session, err := c.sessionStorage.GetResetPasswordSession(task.Context, task.Token)
	if err != nil {
		if r := redirectToPasswordErrorPageIfConfigured(resetSettings.ErrorRedirectURL); r != nil {
			return r
		}
		return ef(loginTypes.NewInternalError("failed to retrieve password reset session", err))
	}
	if session == nil {
		if r := redirectToPasswordErrorPageIfConfigured(resetSettings.ErrorRedirectURL); r != nil {
			return r
		}
		return ef(loginTypes.ResetPasswordSessionExpiredOrDoesNotExistError)
	}

	err = c.sessionStorage.DropResetPasswordSession(task.Context, task.Token)
	if err != nil {
		if r := redirectToPasswordErrorPageIfConfigured(resetSettings.ErrorRedirectURL); r != nil {
			return r
		}
		return ef(loginTypes.NewInternalError("failed to drop password reset session", err))
	}

	input := &cognitoidentityprovider.ForgotPasswordInput{
		ClientId: aws.String(c.cfg.Client.ID),
		Username: aws.String(session.User),
	}

	if c.cfg.Client.Secret != "" {
		input.SecretHash = aws.String(computeSecretHash(c.cfg.Client.Secret, session.User, c.cfg.Client.ID))
	}

	result, err := c.cognitoClient.ForgotPassword(task.Context, input)

	if err != nil {
		if r := redirectToPasswordErrorPageIfConfigured(resetSettings.ErrorRedirectURL); r != nil {
			return r
		}
		return ef(loginTypes.NewInternalError("no password error redirect configured", err))
	}

	token, err := tools.GenerateRandomString(32)
	if err != nil {
		requestLogger.Error("unable to generate token", zap.Error(err))
	}

	if err := c.sessionStorage.CreateConfirmPasswordResetSession(task.Context, token, session.User, time.Now().Add(resetSettings.ValidFor)); err != nil {
		requestLogger.Error("failed to create password reset session", zap.Error(err))
		if r := redirectToPasswordErrorPageIfConfigured(resetSettings.ErrorRedirectURL); r != nil {
			return r
		}
		return ef(loginTypes.NewInternalError("failed to create password reset confirmation session", err))
	}

	requestLogger.Info("user password has been reset",
		zap.String("user", session.User),
		zap.String("deliveryMethod", string(result.CodeDeliveryDetails.DeliveryMedium)),
		zap.String("destination", *result.CodeDeliveryDetails.Destination),
	)

	return &resetPasswordTaskResult{
		redirectTo: fmt.Sprintf(resetSettings.RedirectURL, token),
	}
}

func redirectToPasswordErrorPageIfConfigured(errorRedirectURL string) *resetPasswordTaskResult {
	if errorRedirectURL != "" {
		return &resetPasswordTaskResult{
			redirectTo: errorRedirectURL,
		}
	}
	return nil
}
