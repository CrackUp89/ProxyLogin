package cognito

import (
	"context"
	"proxylogin/internal/manager/logging"
	loginTypes "proxylogin/internal/manager/login/types"
	"proxylogin/internal/manager/tools"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	cognitoClientID          = ""
	cognitoClientSecret      = ""
	cognitoUserPoolID        = ""
	cognitoJWKSIssuer        = ""
	cognitoJWKSKeySigningURL = ""
	loginSessionValidFor     time.Duration
	jwksValidator            *tools.JWKSValidator
	useAuthToRefresh         bool
	awsConfig                aws.Config
	cognitoClient            *cognitoidentityprovider.Client
	sesClient                *ses.Client
	poolClientDescription    *types.UserPoolClientType
	poolDescription          *types.UserPoolType
	stopWorkers              func()
)

const (
	AuthContextVarName         = "cognito_auth"
	IdTokenContextVarName      = "cognito_id"
	RefreshTokenContextVarName = "refresh_id"
)

var cognitoLogger *zap.Logger

func getLogger() *zap.Logger {
	if cognitoLogger == nil {
		cognitoLogger = logging.NewLogger("cognito")
	}
	return cognitoLogger
}

func loadSettings() error {

	cognitoClientID = viper.GetString("cognito.clientId")
	cognitoClientSecret = viper.GetString("cognito.clientSecret")
	cognitoUserPoolID = viper.GetString("cognito.userPoolId")
	cognitoJWKSIssuer = viper.GetString("cognito.jwksIssuer")
	cognitoJWKSKeySigningURL = viper.GetString("cognito.jwksSigningKeyURL")

	err := validateSettings()
	if err != nil {
		return err
	}

	poolClientDescription = describeUserPoolClient(cognitoClient, cognitoUserPoolID, cognitoClientID)
	poolDescription = describeUserPool(cognitoClient, cognitoUserPoolID)

	useAuthToRefresh = poolClientDescription.EnableTokenRevocation != nil && *poolClientDescription.EnableTokenRevocation

	if poolClientDescription.AuthSessionValidity != nil {
		loginSessionValidFor = time.Duration(*poolClientDescription.AuthSessionValidity*60) * time.Second
	}

	jwksValidator, err = tools.NewJWKSValidator(cognitoJWKSKeySigningURL, cognitoJWKSIssuer, "")

	if err != nil {
		return err
	}

	loadProcessingSettings()

	createSessionsStorage()

	return nil
}

func validateSettings() error {
	validationIssues := make(map[string]string)

	if cognitoClientID == "" {
		validationIssues["cognito.clientId"] = "must be set"
	}
	if cognitoClientSecret == "" {
		validationIssues["cognito.clientSecret"] = "must be set"
	}
	if cognitoUserPoolID == "" {
		validationIssues["cognito.userPoolId"] = "must be set"
	}
	if cognitoJWKSIssuer == "" {
		validationIssues["cognito.jwksIssuer"] = "must be set"
	}
	if cognitoJWKSKeySigningURL == "" {
		validationIssues["cognito.jwksSigningKeyURL"] = "must be set"
	}

	if len(validationIssues) > 0 {
		return loginTypes.NewValidationError(validationIssues)
	}
	return nil
}

func describeUserPoolClient(client *cognitoidentityprovider.Client, userPoolId, clientId string) *types.UserPoolClientType {
	input := &cognitoidentityprovider.DescribeUserPoolClientInput{
		UserPoolId: aws.String(userPoolId),
		ClientId:   aws.String(clientId),
	}

	result, err := client.DescribeUserPoolClient(context.Background(), input)

	if err != nil {
		getLogger().Fatal("Failed to describe user pool", zap.Error(err))
	}
	return result.UserPoolClient
}

func describeUserPool(client *cognitoidentityprovider.Client, userPoolId string) *types.UserPoolType {
	input := &cognitoidentityprovider.DescribeUserPoolInput{
		UserPoolId: aws.String(userPoolId),
	}

	result, err := client.DescribeUserPool(context.Background(), input)

	if err != nil {
		getLogger().Fatal("Failed to describe user pool", zap.Error(err))
	}

	return result.UserPool
}

func Start() error {
	var err error
	awsConfig, err = config.LoadDefaultConfig(context.Background())
	if err != nil {
		return err
	}
	cognitoClient = cognitoidentityprovider.NewFromConfig(awsConfig)
	sesClient = ses.NewFromConfig(awsConfig)

	err = loadSettings()
	if err != nil {
		return err
	}

	stopWorkers = StartWorkers(viper.GetUint64("cognito.workers"))

	return nil
}

func Stop() {
	if stopWorkers != nil {
		stopWorkers()
	}
}
