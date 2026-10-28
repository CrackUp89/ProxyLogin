package cognito

import (
	"context"
	"encoding/json"
	"fmt"
	loginTypes "proxylogin/internal/manager/login/types"
	"proxylogin/internal/manager/tools"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitoTypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	sesTypes "github.com/aws/aws-sdk-go-v2/service/ses/types"
	"go.uber.org/zap"
)

type initiatePasswordResetTaskResult struct {
	withResultBase
	withPayload
}

type initiatePasswordResetTaskResultChan chan *initiatePasswordResetTaskResult

type initiatePasswordResetTask struct {
	Email string
	Task[initiatePasswordResetTaskResult, *initiatePasswordResetTaskResult]
}

func (t initiatePasswordResetTask) Process(c *Cognito) {
	t.ResultChan <- c.processInitiatePasswordResetTask(t)
}

func (c *Cognito) createInitiatePasswordResetTask(ctx context.Context, email string) (initiatePasswordResetTaskResultChan, loginTypes.GenericError) {
	resultChan := make(initiatePasswordResetTaskResultChan)
	err := c.appendInitiatePasswordResetTask(initiatePasswordResetTask{email, Task[initiatePasswordResetTaskResult, *initiatePasswordResetTaskResult]{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

func (c *Cognito) processInitiatePasswordResetTask(task initiatePasswordResetTask) *initiatePasswordResetTaskResult { //todo: only works with email. add ability to reset by user name (disabled by default)
	ef := genericTaskErrorFactory[initiatePasswordResetTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(c.processingLogLevel, "processing", zap.String("email", task.Email))

	defer func() {
		time.Sleep(100 * time.Millisecond) //always sleep a bit

		users, err := c.findUsersByEmail(context.Background(), task.Email)
		if err != nil {
			requestLogger.Error("unable to retrieve user", zap.Error(err))
			return
		}

		if len(users) > 1 {
			requestLogger.Error("found multiple users with the same email", zap.String("email", task.Email))
		} else if len(users) == 0 {
			requestLogger.Warn("attempted password recovery for non existing email", zap.String("email", task.Email))
		} else {
			token, err := tools.GenerateRandomString(32)
			if err != nil {
				requestLogger.Error("unable to generate token", zap.Error(err))
			}
			user := users[0]

			var email string
			for _, attr := range user.Attributes {
				if *attr.Name == "email" {
					email = *attr.Value
				}
			}

			//todo: check if email verified if required

			if email == "" {
				requestLogger.Warn("user has no email configured - using address provided in request", zap.String("email", task.Email))
				email = task.Email
			}

			resetSettings := c.appConfig.PasswordResetConfig

			if err := c.sessionStorage.CreateResetPasswordSession(context.Background(), token, *user.Username, email, time.Now().Add(resetSettings.ValidFor)); err != nil {
				requestLogger.Error("failed to create password reset session", zap.Error(err))
				return
			}

			resetLink := fmt.Sprintf("%s/password/reset?token=%s", c.appConfig.URLBase, token)

			templateData := map[string]any{
				"username":      *user.Username,
				"resetLink":     resetLink,
				"expiryMinutes": uint64(resetSettings.ValidFor.Minutes()),
				"companyName":   resetSettings.Company,
				"currentYear":   resetSettings.Year,
			}

			templateJSON, err := json.Marshal(templateData)
			if err != nil {
				requestLogger.Error("failed to marshal template data", zap.Error(err))
				return
			}

			input := &ses.SendTemplatedEmailInput{
				Source: aws.String(resetSettings.Sender),
				Destination: &sesTypes.Destination{
					ToAddresses: []string{email},
				},
				Template:     aws.String(resetSettings.TemplateName),
				TemplateData: aws.String(string(templateJSON)),
			}

			result, err := c.sesClient.SendTemplatedEmail(context.Background(), input)
			if err != nil {
				requestLogger.Error("failed to send an email", zap.Error(err))
				return
			}

			requestLogger.Info("sent reset password message", zap.String("email", email),
				zap.String("user", *user.Username),
				zap.String("messageId", *result.MessageId))
		}
	}()

	return &initiatePasswordResetTaskResult{}
}

func (c *Cognito) findUsersByEmail(ctx context.Context, email string) ([]cognitoTypes.UserType, loginTypes.GenericError) {
	if strings.ContainsAny(email, "\\\"'") {
		return nil, loginTypes.GenericInvalidEmailError
	}
	filter := fmt.Sprintf("email = \"%s\"", email)

	input := &cognitoidentityprovider.ListUsersInput{
		UserPoolId: aws.String(c.cfg.UserPoolID),
		Filter:     aws.String(filter),
		Limit:      aws.Int32(2),
	}

	result, err := c.cognitoClient.ListUsers(ctx, input)
	if err != nil {
		return nil, loginTypes.NewInternalError("unable to list users by email", err)
	}

	return result.Users, nil
}

type PasswordResetData struct {
	Username      string `json:"username"`
	ResetLink     string `json:"resetLink"`
	ExpiryMinutes int    `json:"expiryMinutes"`
	CompanyName   string `json:"companyName"`
	CurrentYear   string `json:"currentYear"`
}
