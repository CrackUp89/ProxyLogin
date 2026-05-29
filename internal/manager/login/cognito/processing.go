package cognito

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	loginTypes "proxylogin/internal/manager/login/types"
	"proxylogin/internal/manager/tools"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitoTypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func (c *Cognito) loadProcessingSettings() {
	if !c.cfg.LogAllRequests {
		c.processingLogLevel = zapcore.DebugLevel
	}
}

func computeSecretHash(clientSecret, username, clientId string) string {
	message := username + clientId
	key := []byte(clientSecret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

type errorFactory[R any, PR interface {
	*R
	WithTaskResultBase
}] func(err loginTypes.GenericError) PR

func checkTaskContext[R any, PR interface {
	*R
	WithTaskResultBase
}](t Task[R, PR], ef errorFactory[R, PR]) PR {
	if err := t.Context.Err(); err != nil {
		return ef(loginTypes.NewInternalError("context error", err))
	}
	return nil
}

func genericTaskErrorFactory[T any, PT interface {
	*T
	SetError(loginTypes.GenericError)
}](err loginTypes.GenericError) PT {
	var zero T
	pt := PT(&zero)
	pt.SetError(err)
	return pt
}

func getRequestLoggerFromContext(ctx context.Context) *zap.Logger {
	return getRequestLogger(ctx).Named("processors")
}

func getRequestLoggerFromTask[R any, PR interface {
	*R
	WithTaskResultBase
}](task Task[R, PR]) *zap.Logger {
	return getRequestLoggerFromContext(task.Context)
}

// todo: add sms
var mfaMapping = map[string]loginTypes.MFAType{
	"SOFTWARE_TOKEN_MFA": loginTypes.MFATypeSoftwareToken,
	"EMAIL_OTP":          loginTypes.MFATypeEMAIL,
}

var reverseMFAMapping = tools.ReverseMap(mfaMapping)

func mapMFAList(mfaTypes []string) []loginTypes.MFAType {
	r := make([]loginTypes.MFAType, 0, len(mfaTypes))
	for _, mfaType := range mfaTypes {
		if m, ok := mfaMapping[strings.Trim(mfaType, "\"")]; ok {
			r = append(r, m)
		}
	}
	return r
}

func (c *Cognito) getUserFromAuthToken(ctx context.Context, accessToken string) (*cognitoidentityprovider.AdminGetUserOutput, loginTypes.GenericError) {
	token, err := c.jwksValidator.ValidateToken(accessToken)

	var username string

	if err != nil {
		return nil, loginTypes.NewGenericAuthError("jwks validation failed", "invalid token", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); token.Valid && ok {
		if un, ok := claims["username"].(string); ok {
			username = un
		}
	} else {
		return nil, loginTypes.NewGenericAuthError("token is invalid or does not contain username", "invalid token", nil)
	}

	input := &cognitoidentityprovider.AdminGetUserInput{
		UserPoolId: aws.String(c.cfg.UserPoolID),
		Username:   aws.String(username),
	}

	result, err := c.cognitoClient.AdminGetUser(ctx, input)
	if err != nil {
		return nil, loginTypes.WrapWithInternalError(err)
	}

	if result == nil {
		return nil, loginTypes.NewInternalError("result is empty", nil)
	}

	return result, nil
}

func (c *Cognito) ensureMFAAfterUpdate(ctx context.Context, accessToken string) loginTypes.GenericError {
	if c.poolDescription.MfaConfiguration == cognitoTypes.UserPoolMfaTypeOptional {

		softwareTokenSettings := &cognitoTypes.SoftwareTokenMfaSettingsType{
			Enabled:      true,
			PreferredMfa: false,
		}

		mfaPreferenceInput := &cognitoidentityprovider.SetUserMFAPreferenceInput{
			AccessToken:              aws.String(accessToken),
			SoftwareTokenMfaSettings: softwareTokenSettings,
		}

		_, err := c.cognitoClient.SetUserMFAPreference(ctx, mfaPreferenceInput)

		if err != nil {
			return loginTypes.NewInternalError("failed to enable software token MFA", err)
		}
	}
	return nil
}
