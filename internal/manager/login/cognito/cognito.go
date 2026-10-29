package cognito

import (
	"context"
	appconfig "proxylogin/internal/manager/config"
	"proxylogin/internal/manager/logging"
	"proxylogin/internal/manager/login/masquerade"
	loginTypes "proxylogin/internal/manager/login/types"
	"proxylogin/internal/manager/ratelimiter"
	"proxylogin/internal/manager/tools"
	"proxylogin/internal/manager/tools/locking"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/danielgtaylor/huma/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	AuthContextVarName          = "cognito_auth"
	IdTokenContextVarName       = "cognito_id"
	RefreshTokenContextVarName  = "refresh_id"
	LoginSessionContextVarName  = "login_session_id"
	CSRFTokenContextVarName     = "csrf_token"
	UpdateSessionContextVarName = "update_session_id"
)

var cognitoLogger *zap.Logger

func getLogger() *zap.Logger {
	if cognitoLogger == nil {
		cognitoLogger = logging.NewLogger("cognito")
	}
	return cognitoLogger
}

type Cognito struct {
	cfg       appconfig.CognitoConfig
	appConfig appconfig.Config

	limiters       *ratelimiter.Factory
	masq           *masquerade.Masquerade
	locks          *locking.Provider
	sessionStorage SessionStorage
	csrf           *tools.CSRF

	verifyUserMFATokenOnLoginLimiter     ratelimiter.TotalLimiter
	verifyUserMFATokenOnLoginLimiterOnce sync.Once

	processingLogLevel zapcore.Level

	awsConfig             aws.Config
	cognitoClient         *cognitoidentityprovider.Client
	sesClient             *ses.Client
	poolClientDescription *types.UserPoolClientType
	poolDescription       *types.UserPoolType
	userPoolMFAConfig     *cognitoidentityprovider.GetUserPoolMfaConfigOutput
	jwksValidator         *tools.JWKSValidator
	useAuthToRefresh      bool
	loginSessionValidFor  time.Duration

	tasks       chan taskWrapper
	stopWorkers func()
	taskAppenders
	withAllowedOriginMiddleware func(ctx huma.Context, next func(huma.Context))
}

// New builds a Cognito login provider from cfg. It does not contact AWS; call Start for that.
func New(cfg appconfig.Config, csrf *tools.CSRF) (*Cognito, error) {
	c := &Cognito{
		cfg:                cfg.CognitoConfig,
		appConfig:          cfg,
		limiters:           ratelimiter.NewFactory(cfg.RateLimiterConfig, cfg.RedisClientConfig),
		locks:              locking.NewProvider(cfg.StorageType, cfg.RedisClientConfig),
		processingLogLevel: zapcore.InfoLevel,
		tasks:              make(chan taskWrapper),
		csrf:               csrf,
	}

	if err := c.validateSettings(); err != nil {
		return nil, err
	}

	var err error
	c.masq, err = masquerade.New(cfg.MasqueradeConfig, cfg.StorageType, cfg.RedisClientConfig)
	if err != nil {
		return nil, err
	}

	if err = c.createSessionsStorage(cfg.StorageType, cfg.RedisClientConfig); err != nil {
		return nil, err
	}

	c.loadProcessingSettings()
	c.initTaskAppenders()

	return c, nil
}

func (c *Cognito) loadSettings() error {
	var err error

	c.poolClientDescription = describeUserPoolClient(c.cognitoClient, c.cfg.UserPoolID, c.cfg.Client.ID)
	c.poolDescription = describeUserPool(c.cognitoClient, c.cfg.UserPoolID)

	c.userPoolMFAConfig = getUserPoolMfaConfig(c.cognitoClient, c.cfg.UserPoolID)

	c.useAuthToRefresh = c.poolClientDescription.EnableTokenRevocation != nil && *c.poolClientDescription.EnableTokenRevocation

	if c.poolClientDescription.AuthSessionValidity != nil {
		c.loginSessionValidFor = time.Duration(*c.poolClientDescription.AuthSessionValidity*60) * time.Second
	}

	c.jwksValidator, err = tools.NewJWKSValidator(c.cfg.JWKSSigningKeyURL, c.cfg.JWKSIssuer, "")

	if err != nil {
		return err
	}

	return nil
}

func (c *Cognito) validateSettings() error {
	validationIssues := make(map[string]string)

	if c.cfg.Client.ID == "" {
		validationIssues["cognito.clientId"] = "must be set"
	}
	if c.cfg.UserPoolID == "" {
		validationIssues["cognito.userPoolId"] = "must be set"
	}
	if c.cfg.JWKSIssuer == "" {
		validationIssues["cognito.jwksIssuer"] = "must be set"
	}
	if c.cfg.JWKSSigningKeyURL == "" {
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

func getUserPoolMfaConfig(client *cognitoidentityprovider.Client, userPoolId string) *cognitoidentityprovider.GetUserPoolMfaConfigOutput {
	input := &cognitoidentityprovider.GetUserPoolMfaConfigInput{
		UserPoolId: aws.String(userPoolId),
	}

	result, err := client.GetUserPoolMfaConfig(context.Background(), input)

	if err != nil {
		getLogger().Fatal("Failed to describe user pool", zap.Error(err))
	}

	return result
}

// Start loads AWS config, describes the user pool and starts task workers.
func (c *Cognito) Start() error {
	var err error
	c.awsConfig, err = config.LoadDefaultConfig(context.Background())
	if err != nil {
		return err
	}
	c.cognitoClient = cognitoidentityprovider.NewFromConfig(c.awsConfig)
	c.sesClient = ses.NewFromConfig(c.awsConfig)

	err = c.loadSettings()
	if err != nil {
		return err
	}

	c.stopWorkers = c.StartWorkers(c.cfg.Workers)

	return nil
}

func (c *Cognito) Stop() {
	if c.stopWorkers != nil {
		c.stopWorkers()
	}
}
