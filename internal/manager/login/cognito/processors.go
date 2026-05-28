package cognito

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"proxylogin/internal/manager/config"
	"proxylogin/internal/manager/login/masquerade"
	"proxylogin/internal/manager/login/passwordreset"
	loginTypes "proxylogin/internal/manager/login/types"
	"proxylogin/internal/manager/tools"
	"proxylogin/internal/manager/tools/locking"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitoTypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	sesTypes "github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var processingLogLevel = zapcore.InfoLevel

func init() {
	viper.SetDefault("cognito.logAllRequests", true)
}

func loadProcessingSettings() {
	if !viper.GetBool("cognito.logAllRequests") {
		processingLogLevel = zapcore.DebugLevel
	}
}

func computeSecretHash(clientSecret, username, clientId string) string {
	message := username + clientId
	key := []byte(clientSecret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func resolveAuthTokenFromContext(ctx context.Context) (string, loginTypes.GenericError) {
	auth := ctx.Value(AuthContextVarName)

	if auth == nil {
		return "", nil
	}

	if t, ok := auth.(TokenAuth); ok {
		return t.Token, nil
	}

	if t, ok := auth.(MasqueradedAuth); ok {
		requestLogger := getRequestLoggerFromContext(ctx)
		token, err := unmaskToken(ctx, t.Token, requestLogger, true, masquerade.UnmaskRefreshToken())
		if err != nil {
			return "", err
		}
		return token.AccessToken, nil
	}

	panic("unknown auth type")
}

func getMasqueradedTokenFromContext(ctx context.Context) string {
	auth := ctx.Value(AuthContextVarName)

	if auth == nil {
		return ""
	}

	if t, ok := auth.(MasqueradedAuth); ok {
		return t.Token
	}

	return ""
}

func getIdTokenFromContext(ctx context.Context) string {
	v := ctx.Value(IdTokenContextVarName)
	if v == nil {
		return ""
	}
	if t, ok := v.(string); ok {
		return t
	}
	return ""
}

func getRefreshTokenFromContext(ctx context.Context) string {
	v := ctx.Value(RefreshTokenContextVarName)
	if v == nil {
		return ""
	}
	if t, ok := v.(string); ok {
		return t
	}
	return ""
}

func validateTokenOrigin(token string) loginTypes.GenericError {
	t, err := jwksValidator.ParseToken(token)
	if t == nil || t.Claims == nil {
		return loginTypes.NewGenericAuthenticationError("unable to parse token or token has no claims", "invalid token", err)
	}

	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return loginTypes.NewGenericAuthenticationError("unable to extract token claims", "invalid token", nil)
	}

	tokenClientId, ok := claims["client_id"].(string)
	if !ok || tokenClientId == "" {
		return loginTypes.NewGenericAuthenticationError("auth token has no client ID", "invalid token", nil)
	}
	if tokenClientId != cognitoClientID {
		return loginTypes.NewGenericAuthenticationError("auth token has invalid client ID", "invalid token", nil)
	}

	issuer, err := t.Claims.GetIssuer()
	if err != nil || issuer == "" {
		return loginTypes.NewGenericAuthenticationError("auth token has no issuer", "invalid token", nil)
	}
	if issuer != cognitoJWKSIssuer {
		return loginTypes.NewGenericAuthenticationError("auth token has invalid issuer", "invalid token", nil)
	}

	return nil
}

func checkAuthToken[R any, PR interface {
	*R
	WithTaskResultBase
}](accessToken string, ef errorFactory[R, PR]) PR {
	if accessToken == "" {
		return ef(loginTypes.UnauthorizedError)
	}

	_, err := jwksValidator.ValidateToken(accessToken)

	if err != nil {
		return ef(loginTypes.NewGenericAuthenticationError("jwks validation failed", "invalid token", err)) //todo: make a generic error type
	}

	return nil
}

func checkAuthContextValue[R any, PR interface {
	*R
	WithTaskResultBase
}](ctx context.Context, ef errorFactory[R, PR]) (string, PR) {
	accessToken, authErr := resolveAuthTokenFromContext(ctx)

	if authErr != nil {
		return "", ef(authErr)
	}

	return accessToken, checkAuthToken(accessToken, ef)
}

type AuthenticationResult struct {
	AccessToken  *string `json:"access_token"`
	IdToken      *string `json:"id_token"`
	RefreshToken *string `json:"refresh_token"`
}

func authenticationResultFromCognitoType(authResult *cognitoTypes.AuthenticationResultType) *AuthenticationResult {
	return &AuthenticationResult{
		AccessToken:  authResult.AccessToken,
		IdToken:      authResult.IdToken,
		RefreshToken: authResult.RefreshToken,
	}
}

func authResultToAuthTokenSet(authResult *AuthenticationResult) (*loginTypes.AuthTokenSet, error) {
	result := loginTypes.AuthTokenSet{
		AccessToken: *authResult.AccessToken,
		IdToken:     *authResult.IdToken,
	}

	if authToken, err := jwksValidator.ParseToken(*authResult.AccessToken); err == nil {
		if authExpires, err := authToken.Claims.GetExpirationTime(); err == nil {
			result.AccessTokenExpires = authExpires.Time
		}
	} else {
		return nil, err
	}

	if idToken, err := jwksValidator.ParseToken(*authResult.IdToken); err == nil {
		if authExpires, err := idToken.Claims.GetExpirationTime(); err == nil {
			result.IdTokenExpires = authExpires.Time
		}
	} else {
		return nil, err
	}

	if authResult.RefreshToken != nil {
		result.RefreshToken = *authResult.RefreshToken
		var expiryDuration time.Duration
		if poolClientDescription.TokenValidityUnits == nil {
			expiryDuration = getDurationFromTokenValidity(poolClientDescription.RefreshTokenValidity, cognitoTypes.TimeUnitsTypeDays)
		} else {
			expiryDuration = getDurationFromTokenValidity(poolClientDescription.RefreshTokenValidity, poolClientDescription.TokenValidityUnits.RefreshToken)
		}
		result.RefreshTokenExpires = time.Now().Add(expiryDuration)
	}
	return &result, nil
}

func getDurationFromTokenValidity(tokenValidity int32, unitType cognitoTypes.TimeUnitsType) time.Duration {
	switch unitType {
	case "":
		fallthrough
	case cognitoTypes.TimeUnitsTypeDays:
		return time.Duration(tokenValidity) * time.Hour * 24
	case cognitoTypes.TimeUnitsTypeHours:
		return time.Duration(tokenValidity) * time.Hour
	case cognitoTypes.TimeUnitsTypeMinutes:
		return time.Duration(tokenValidity) * time.Minute
	case cognitoTypes.TimeUnitsTypeSeconds:
		return time.Duration(tokenValidity) * time.Second
	}
	panic(fmt.Sprintf("invalid token validity unit type: %s", unitType))
}

func authResultToMasqueradedToken(ctx context.Context, authResult *AuthenticationResult, user string) (*loginTypes.MasqueradedToken, error) {
	key, err := masquerade.GetNewKey(ctx)
	if err != nil {
		return nil, err
	}

	var expires time.Time
	tokenSet := make(masquerade.TokenSet, 3)

	authTokenRecord := masquerade.TokenRecord{
		Value: *authResult.AccessToken,
	}
	idTokenRecord := masquerade.TokenRecord{
		Value: *authResult.IdToken,
	}

	if authToken, err := jwksValidator.ParseToken(*authResult.AccessToken); err == nil {
		if tokenExpires, err := authToken.Claims.GetExpirationTime(); err == nil {
			authTokenRecord.Expires = tokenExpires.Time
			if tokenExpires.Time.After(expires) {
				expires = tokenExpires.Time
			}
		}
	} else {
		return nil, err
	}

	if idToken, err := jwksValidator.ParseToken(*authResult.IdToken); err == nil {
		if tokenExpires, err := idToken.Claims.GetExpirationTime(); err == nil {
			idTokenRecord.Expires = tokenExpires.Time
			if tokenExpires.Time.After(expires) {
				expires = tokenExpires.Time
			}
		}
	} else {
		return nil, err
	}

	tokenSet[loginTypes.AuthTokenType] = authTokenRecord
	tokenSet[loginTypes.IDTokenType] = idTokenRecord

	if authResult.RefreshToken != nil {
		var expiryDuration time.Duration
		if poolClientDescription.TokenValidityUnits == nil {
			expiryDuration = getDurationFromTokenValidity(poolClientDescription.RefreshTokenValidity, cognitoTypes.TimeUnitsTypeDays)
		} else {
			expiryDuration = getDurationFromTokenValidity(poolClientDescription.RefreshTokenValidity, poolClientDescription.TokenValidityUnits.RefreshToken)
		}
		tokenExpires := time.Now().Add(expiryDuration)

		if tokenExpires.After(expires) {
			expires = tokenExpires
		}

		tokenSet[loginTypes.RefreshTokenType] = masquerade.TokenRecord{
			Value:   *authResult.RefreshToken,
			Expires: expires,
		}
	}

	mr := &masquerade.MasqueradedRecord{
		Tokens: tokenSet,
		User:   user,
	}

	err = masquerade.GetStorage().StoreMasqueradedRecord(ctx, key, mr, expires)
	if err != nil {
		return nil, err
	}

	return &loginTypes.MasqueradedToken{
		Token:        key,
		TokenExpires: expires,
	}, nil
}

func authResultToPayload(ctx context.Context, authResult *AuthenticationResult, user string) (AuthResultsData, error) {
	if config.UseCookies() && config.UseMasquerade() {
		return authResultToMasqueradedToken(ctx, authResult, user)
	}
	return authResultToAuthTokenSet(authResult)
}

type authResultsFactory[R any, PR interface {
	*R
	WithTaskResultBase
}] func(authResults AuthResultsData, remember bool) PR
type authErrorFactory[R any, PR interface {
	*R
	WithTaskResultBase
}] func(err loginTypes.GenericError, logout bool) PR

type nextStepFactory[R any, PR interface {
	*R
	WithTaskResultBase
}] func(step *NextLoginStep) PR

func enforceMFAAfterAuth[R any, PR interface {
	*R
	WithTaskResultBase
}](ctx context.Context, sessionKey string, authResults *AuthenticationResult, rememberUser bool,
	nsf nextStepFactory[R, PR], ef authErrorFactory[R, PR], logger *zap.Logger) PR {
	if poolDescription.MfaConfiguration == cognitoTypes.UserPoolMfaTypeOff {
		logger.Error("unable to enforce mfa - MFA is disabled in the User Pool configuration")
		return nil
	}

	if poolDescription.MfaConfiguration == cognitoTypes.UserPoolMfaTypeOptional {

		result, er := getUserFromAuthToken(ctx, *authResults.AccessToken)

		if er != nil {
			return ef(er, false)
		}

		if result.UserMFASettingList != nil && len(result.UserMFASettingList) > 0 {
			return nil
		}

		nextStep := NextStepMFASetup

		availableMethods := make([]string, 0, 3)

		if userPoolMFAConfig.EmailMfaConfiguration != nil {
			availableMethods = append(availableMethods, "email")
		}

		if userPoolMFAConfig.SoftwareTokenMfaConfiguration != nil && userPoolMFAConfig.SoftwareTokenMfaConfiguration.Enabled {
			availableMethods = append(availableMethods, "software_token")
		}

		//TODO: find a better way to detect if SMS is configured
		if userPoolMFAConfig.SmsMfaConfiguration != nil && userPoolMFAConfig.SmsMfaConfiguration.SmsAuthenticationMessage != nil {
			availableMethods = append(availableMethods, "sms")
		}

		if len(availableMethods) == 0 {
			return ef(loginTypes.NewInternalError("no MFA methods available to setup for user", nil), false)
		}

		expires := time.Now().Add(loginSessionValidFor)

		if err := sessionStorage.CreateMFAEnforcementSession(ctx, sessionKey, rememberUser, authResults, expires); err != nil {
			return ef(loginTypes.NewInternalError("failed to create MFA enforcement session", err), false)
		}

		if err := sessionStorage.CreateLoginSession(ctx, sessionKey, "",
			nextStep, NextStepVariantMFAEnforcement, rememberUser, expires, nil); err != nil {
			return ef(loginTypes.NewInternalError("failed to create login session", err), false)
		}

		nls := &NextLoginStep{}
		nls.SetSession(sessionKey)
		nls.SetNextStep(nextStep)

		nls.SetPayload(map[string]interface{}{
			"available_mfa_methods": availableMethods,
		})

		return nsf(nls)
	}

	return nil
}

func handleFinalAuthResults[R any, PR interface {
	*R
	WithTaskResultBase
}](ctx context.Context, authResults *AuthenticationResult, user string, remember bool,
	rf authResultsFactory[R, PR], ef authErrorFactory[R, PR]) PR {

	authPayload, err := authResultToPayload(ctx, authResults, user)
	return handleAuthPayload(authPayload, remember, err, rf, ef)
}

func handleAuthResults[R any, PR interface {
	*R
	WithTaskResultBase
}](ctx context.Context, authResults *AuthenticationResult, user string, remember bool,
	sessionKey string,
	rf authResultsFactory[R, PR], nsf nextStepFactory[R, PR], ef authErrorFactory[R, PR], logger *zap.Logger) PR {

	if enforceMFA {
		if r := enforceMFAAfterAuth(ctx, sessionKey, authResults, remember, nsf, ef, logger); r != nil {
			return r
		}
	}

	return handleFinalAuthResults(ctx, authResults, user, remember, rf, ef)
}

func handleAuthPayload[R any, PR interface {
	*R
	WithTaskResultBase
}](authPayload AuthResultsData, remember bool, err error,
	rf authResultsFactory[R, PR], ef authErrorFactory[R, PR]) PR {
	if err != nil {
		if ge, ok := errors.AsType[loginTypes.GenericError](err); ok {
			return ef(ge, true)
		}

		return ef(loginTypes.NewInternalError("auth payload error", err), true)
	}
	return rf(authPayload, remember)
}

func tokenSetToAuthPayload(tokenSet masquerade.TokenSet, appendRefreshToken bool) *loginTypes.AuthTokenSet {
	r := &loginTypes.AuthTokenSet{
		AccessToken:        tokenSet[loginTypes.AuthTokenType].Value,
		AccessTokenExpires: tokenSet[loginTypes.AuthTokenType].Expires,
		IdToken:            tokenSet[loginTypes.IDTokenType].Value,
		IdTokenExpires:     tokenSet[loginTypes.IDTokenType].Expires,
	}
	if appendRefreshToken {
		if s, ok := tokenSet[loginTypes.RefreshTokenType]; ok {
			r.RefreshToken = s.Value
			r.RefreshTokenExpires = s.Expires
		}
	}
	return r
}

func handleChallenge[R any, PR interface {
	*R
	WithTaskResultBase
}](challenge cognitoTypes.ChallengeNameType, challengeParameters map[string]string,
	ctx context.Context, cognitoSessions string, sessionKey string, rememberUser bool,
	rf nextStepFactory[R, PR],
	ef errorFactory[R, PR]) PR {

	if challenge == "" {
		return ef(loginTypes.NewInternalError("challenge is empty", nil))
	}

	nls := &NextLoginStep{}
	nls.SetSession(sessionKey)

	var sessionTag interface{} = nil
	var nextStep NextStep

	switch challenge {
	case cognitoTypes.ChallengeNameTypeSelectMfaType:
		nextStep = NextStepMFASelect
		v, ok := challengeParameters["MFAS_CAN_CHOOSE"]
		if ok {
			nls.SetPayload(map[string]interface{}{
				"available_mfa_methods": mapMFAList(strings.Split(strings.Trim(v, "[]"), ",")),
			})
		} else {
			return ef(loginTypes.NewInternalError("no MFA methods available for user login", nil))
		}
		break
	case cognitoTypes.ChallengeNameTypeMfaSetup:
		nextStep = NextStepMFASetup
		v, ok := challengeParameters["MFAS_CAN_SETUP"]
		if ok {
			nls.SetPayload(map[string]interface{}{
				"available_mfa_methods": mapMFAList(strings.Split(strings.Trim(v, "[]"), ",")),
			})
		} else {
			return ef(loginTypes.NewInternalError("no MFA methods available to setup for user", nil))
		}
		break
	case cognitoTypes.ChallengeNameTypeSoftwareTokenMfa:
		nextStep = NextStepMFASoftwareTokenVerify
		break
	case cognitoTypes.ChallengeNameTypeEmailOtp:
		nextStep = NextStepMFAEMailVerify
		break
	case cognitoTypes.ChallengeNameTypeSmsMfa:
		nextStep = NextStepMFASMSVerify
		break
	case cognitoTypes.ChallengeNameTypeNewPasswordRequired:
		nextStep = NextStepNewPassword
		v, ok := challengeParameters["requiredAttributes"]
		if ok {
			nls.SetPayload(map[string]interface{}{
				"required": v,
			})
			sessionTag = v
		}
		break
	default:
		return ef(loginTypes.NewInternalError("unsupported challenge type: "+string(challenge), nil))
	}

	if err := sessionStorage.CreateLoginSession(ctx, sessionKey, cognitoSessions, nextStep, NextStepVariantDefault, rememberUser, time.Now().Add(loginSessionValidFor), sessionTag); err != nil {
		return ef(loginTypes.NewInternalError("failed to create login session", err))
	}

	nls.SetNextStep(nextStep)

	return rf(nls)
}

func getLoginSession[R any, PR interface {
	*R
	WithTaskResultBase
}](ctx context.Context, sessionKey string, ef errorFactory[R, PR]) (*LoginSession, PR) {
	session, err := sessionStorage.GetLoginSession(ctx, sessionKey)
	if err != nil {
		return nil, ef(loginTypes.NewInternalError("failed to retrieve login session", err))
	}
	if session == nil {
		return nil, ef(loginTypes.NewLoginSessionExpiredOrDoesNotExistError())
	}
	return session, nil
}

func getMFAEnforcementSession[R any, PR interface {
	*R
	WithTaskResultBase
}](ctx context.Context, sessionKey string, ef errorFactory[R, PR]) (*MFAEnforcementSession, PR) {
	session, err := sessionStorage.GetMFAEnforcementSession(ctx, sessionKey)
	if err != nil {
		return nil, ef(loginTypes.NewInternalError("failed to retrieve MFA enforcement session", err))
	}
	if session == nil {
		return nil, ef(loginTypes.NewLoginSessionExpiredOrDoesNotExistError())
	}
	return session, nil
}

func checkNextStep[R any, PR interface {
	*R
	WithTaskResultBase
}](s *LoginSession, expectedStep NextStep, ef errorFactory[R, PR]) PR {
	if s.NextStep != expectedStep {
		return ef(loginTypes.NewBadRequestError(fmt.Sprintf("unexpected next step: %s; expected: %s", s.NextStep, expectedStep), "unexpected next step", nil))
	}
	return nil
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

func dropLoginSession(ctx context.Context, loginSessionKey string) error {
	return sessionStorage.DropLoginSession(ctx, loginSessionKey)
}

func dropMFAEnforcementSession(ctx context.Context, sessionKey string) error {
	return sessionStorage.DropMFAEnforcementSession(ctx, sessionKey)
}

func genericAuthResultFactory[R any, PT interface {
	*R
	SetAuthResults(results AuthResults)
}](r AuthResultsData, remember bool) PT {
	var ar R
	arp := PT(&ar)
	arp.SetAuthResults(&authResults{
		authResultsData: r,
		remember:        remember,
	})
	return arp
}

func genericAuthErrorFactory[R any, PT interface {
	*R
	SetAuthResults(results AuthResults)
	SetError(genericError loginTypes.GenericError)
	AddSideEffect(sideEffect SideEffect)
}](err loginTypes.GenericError, logout bool) PT {
	var er R
	erp := PT(&er)
	erp.SetAuthResults(&authResults{
		authResultsData: nil,
		remember:        false,
	})
	erp.SetError(err)
	if logout {
		erp.AddSideEffect(SideEffectOutput{Type: LogOutSideEffect})
	}
	return erp
}

func genericNextStepFactory[R any, PT interface {
	*R
	SetNextLoginStep(*NextLoginStep)
}](step *NextLoginStep) PT {
	var er R
	erp := PT(&er)
	erp.SetNextLoginStep(step)
	return erp
}

func processLoginTask(task loginTask) *loginStepResult {
	ef := genericTaskErrorFactory[loginStepResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	unlockSession := lockLoginSession(task.SessionKey)
	defer unlockSession()

	requestLogger.Log(processingLogLevel, "processing", zap.String("sessionKey", task.SessionKey), zap.String("username", task.User))

	authInput := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: cognitoTypes.AuthFlowTypeUserPasswordAuth,
		ClientId: aws.String(cognitoClientID),
		AuthParameters: map[string]string{
			"USERNAME": task.User,
			"PASSWORD": task.Password,
		},
	}

	if cognitoClientSecret != "" {
		authInput.AuthParameters["SECRET_HASH"] = computeSecretHash(cognitoClientSecret, task.User, cognitoClientID)
	}

	result, err := cognitoClient.InitiateAuth(task.Context, authInput)

	if err != nil {
		var ip *cognitoTypes.NotAuthorizedException
		if _, ok := errors.AsType[*cognitoTypes.UserNotFoundException](err); ok || errors.As(err, &ip) {
			return ef(loginTypes.InvalidUserOrPasswordError)
		}

		return ef(loginTypes.NewInternalError("unable to log in", err))
	}

	nsf := genericNextStepFactory[loginStepResult]

	if result.ChallengeName == "" {
		if result.AuthenticationResult != nil {
			if r := handleAuthResults(task.Task.Context, authenticationResultFromCognitoType(result.AuthenticationResult),
				task.User, task.RememberUser, task.SessionKey,
				genericAuthResultFactory[loginStepResult], nsf, genericAuthErrorFactory[loginStepResult], requestLogger); r != nil {
				return r
			}
		}
		return ef(NoChallengeOrAuthenticationResultError)
	}

	return handleChallenge(result.ChallengeName, result.ChallengeParameters, task.Task.Context, *result.Session, task.SessionKey, task.RememberUser,
		nsf, ef)
}

func processMFASetupTask(task mfaSetupTask) *mfaSetupTaskResult {
	ef := genericTaskErrorFactory[mfaSetupTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	unlockSession := lockLoginSession(task.SessionKey)
	defer unlockSession()

	requestLogger.Log(processingLogLevel, "processing", zap.String("sessionKey", task.SessionKey), zap.String("username", task.User))

	var session *LoginSession
	if s, r := getLoginSession(task.Task.Context, task.SessionKey, ef); r == nil {
		session = s
	} else {
		return r
	}

	if r := checkNextStep(session, NextStepMFASetup, ef); r != nil {
		return r
	}

	switch task.MFAType {
	case loginTypes.MFATypeSoftwareToken:

		var associateInput *cognitoidentityprovider.AssociateSoftwareTokenInput
		var nextStepVariant NextStepVariant
		var mfaSession *MFAEnforcementSession = nil

		if session.NextStepVariant == NextStepVariantMFAEnforcement {
			if s, r := getMFAEnforcementSession(task.Context, task.SessionKey, ef); r == nil {
				mfaSession = s
			} else {
				return r
			}

			associateInput = &cognitoidentityprovider.AssociateSoftwareTokenInput{
				AccessToken: mfaSession.AuthenticationResult.AccessToken,
			}
			nextStepVariant = NextStepVariantMFAEnforcement
		} else {
			associateInput = &cognitoidentityprovider.AssociateSoftwareTokenInput{
				Session: aws.String(session.CognitoSession),
			}
			nextStepVariant = NextStepVariantDefault
		}

		associateResult, err := cognitoClient.AssociateSoftwareToken(task.Context, associateInput)
		if err != nil {
			return ef(loginTypes.WrapWithInternalError(err))
		}

		expiration := time.Now().Add(loginSessionValidFor)

		cognitoSession := ""
		if associateResult.Session != nil {
			cognitoSession = *associateResult.Session
		}

		if err := sessionStorage.CreateLoginSession(task.Context, task.SessionKey, cognitoSession, NextStepMFASoftwareTokenSetupVerify, nextStepVariant, session.RememberUser, expiration, nil); err != nil {
			return ef(loginTypes.NewInternalError("failed to create login session", err))
		}

		if mfaSession != nil {
			if err := sessionStorage.CreateMFAEnforcementSession(task.Context, task.SessionKey, session.RememberUser, mfaSession.AuthenticationResult, expiration); err != nil {
				return ef(loginTypes.NewInternalError("failed to create MFA enforcement session", err))
			}
		}

		return &mfaSetupTaskResult{
			withNextLoginStep: withNextLoginStep{
				nextLoginStep: &NextLoginStep{
					Step:    NextStepMFASoftwareTokenSetupVerify,
					Session: task.SessionKey,
					withPayload: withPayload{
						Payload: associateResult.SecretCode,
					},
				},
			},
		}
	}

	return ef(loginTypes.NewBadRequestError("unsupported MFA setup type", "unsupported MFA setup type", nil))
}

func processMFASetupVerifySoftwareTokenTask(task mfaSetupVerifySoftwareTokenTask) *mfaSetupVerifySoftwareTokenTaskResult {
	ef := genericTaskErrorFactory[mfaSetupVerifySoftwareTokenTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	unlockSession := lockLoginSession(task.SessionKey)
	defer unlockSession()

	requestLogger.Log(processingLogLevel, "processing", zap.String("sessionKey", task.SessionKey), zap.String("username", task.User))

	var session *LoginSession
	if s, r := getLoginSession(task.Task.Context, task.SessionKey, ef); r == nil {
		session = s
	} else {
		return r
	}

	if r := checkNextStep(session, NextStepMFASoftwareTokenSetupVerify, ef); r != nil {
		return r
	}

	verifyInput := &cognitoidentityprovider.VerifySoftwareTokenInput{
		UserCode: aws.String(task.Code),
		//FriendlyDeviceName: aws.String("MyDevice"), // Optional device name
	}

	var mfaSession *MFAEnforcementSession
	if session.NextStepVariant == NextStepVariantMFAEnforcement {
		if s, r := getMFAEnforcementSession(task.Context, task.SessionKey, ef); r == nil {
			mfaSession = s
		} else {
			return r
		}
		verifyInput.AccessToken = mfaSession.AuthenticationResult.AccessToken
	} else {
		verifyInput.Session = aws.String(session.CognitoSession)
	}

	verifyResult, err := cognitoClient.VerifySoftwareToken(task.Context, verifyInput)
	if err != nil {
		if _, ok := errors.AsType[*cognitoTypes.EnableSoftwareTokenMFAException](err); ok {
			return ef(loginTypes.InvalidMFACodeError)
		}
		return ef(loginTypes.WrapWithInternalError(err))
	}

	if verifyResult.Status != cognitoTypes.VerifySoftwareTokenResponseTypeSuccess {
		return ef(InconclusiveResponseError)
	}

	nsf := genericNextStepFactory[mfaSetupVerifySoftwareTokenTaskResult]

	if mfaSession != nil {
		if err := ensureMFAAfterUpdate(task.Context, *mfaSession.AuthenticationResult.AccessToken); err != nil {
			return ef(loginTypes.NewInternalError("failed to enable software token MFA", err))
		}

		if r := handleFinalAuthResults(task.Task.Context, mfaSession.AuthenticationResult,
			task.User, session.RememberUser,
			genericAuthResultFactory[mfaSetupVerifySoftwareTokenTaskResult], genericAuthErrorFactory[mfaSetupVerifySoftwareTokenTaskResult]); r != nil {
			return r
		}

		if err := dropMFAEnforcementSession(task.Context, task.SessionKey); err != nil {
			requestLogger.Error("failed to drop MFA enforcement session", zap.Error(err))
		}

		return ef(loginTypes.NewInternalError("no auth response", nil))
	}

	challengeInput := &cognitoidentityprovider.RespondToAuthChallengeInput{
		ChallengeName: cognitoTypes.ChallengeNameTypeMfaSetup,
		ClientId:      aws.String(cognitoClientID),
		Session:       verifyResult.Session,
		ChallengeResponses: map[string]string{
			"USERNAME": task.User,
		},
	}

	if cognitoClientSecret != "" {
		challengeInput.ChallengeResponses["SECRET_HASH"] = computeSecretHash(cognitoClientSecret, task.User, cognitoClientID)
	}

	finalResult, err := cognitoClient.RespondToAuthChallenge(task.Context, challengeInput)
	if err != nil {
		return ef(loginTypes.WrapWithInternalError(err))
	}

	if finalResult.AuthenticationResult != nil {
		if r := handleAuthResults(task.Task.Context, authenticationResultFromCognitoType(finalResult.AuthenticationResult),
			task.User, session.RememberUser, task.SessionKey,
			genericAuthResultFactory[mfaSetupVerifySoftwareTokenTaskResult], nsf, genericAuthErrorFactory[mfaSetupVerifySoftwareTokenTaskResult], requestLogger); r != nil {
			return r
		}
	}

	return handleChallenge(finalResult.ChallengeName, finalResult.ChallengeParameters, task.Task.Context, *finalResult.Session, task.SessionKey, session.RememberUser,
		nsf, ef)
}

func verifyMFACode(session *LoginSession, task mfaVerifyTask, step NextStep) *mfaVerifyTaskResult {
	ef := genericTaskErrorFactory[mfaVerifyTaskResult]

	requestLogger := getRequestLoggerFromTask(task.Task)

	challengeResp := &cognitoidentityprovider.RespondToAuthChallengeInput{
		ClientId: aws.String(cognitoClientID),
		Session:  aws.String(session.CognitoSession),
		ChallengeResponses: map[string]string{
			"USERNAME": task.User,
		},
	}

	if cognitoClientSecret != "" {
		challengeResp.ChallengeResponses["SECRET_HASH"] = computeSecretHash(cognitoClientSecret, task.User, cognitoClientID)
	}

	switch step {
	case NextStepMFASoftwareTokenVerify:
		challengeResp.ChallengeName = cognitoTypes.ChallengeNameTypeSoftwareTokenMfa
		challengeResp.ChallengeResponses["SOFTWARE_TOKEN_MFA_CODE"] = task.Code
		break
	case NextStepMFAEMailVerify:
		challengeResp.ChallengeName = cognitoTypes.ChallengeNameTypeEmailOtp
		challengeResp.ChallengeResponses["EMAIL_OTP_CODE"] = task.Code
		break
	case NextStepMFASMSVerify:
		challengeResp.ChallengeName = cognitoTypes.ChallengeNameTypeSmsMfa
		challengeResp.ChallengeResponses["SMS_OTP_CODE"] = task.Code
		break
	}

	result, err := cognitoClient.RespondToAuthChallenge(task.Context, challengeResp)
	if err != nil {
		if _, ok := errors.AsType[*cognitoTypes.CodeMismatchException](err); ok {
			return ef(loginTypes.NewBadRequestError("invalid MFA code", "invalid MFA code", err))
		}
		if _, ok := errors.AsType[*cognitoTypes.NotAuthorizedException](err); ok {
			return ef(loginTypes.UnauthorizedError)
		}
		return ef(loginTypes.WrapWithInternalError(err))
	}

	nsf := genericNextStepFactory[mfaVerifyTaskResult]

	if result.ChallengeName == "" {
		if result.AuthenticationResult != nil {
			if r := handleAuthResults(task.Task.Context, authenticationResultFromCognitoType(result.AuthenticationResult),
				task.User, session.RememberUser, task.SessionKey,
				genericAuthResultFactory[mfaVerifyTaskResult], nsf, genericAuthErrorFactory[mfaVerifyTaskResult], requestLogger); r != nil {
				return r
			}
		}
		return ef(NoChallengeOrAuthenticationResultError)
	}

	return handleChallenge(result.ChallengeName, result.ChallengeParameters, task.Task.Context, *result.Session, task.SessionKey, session.RememberUser,
		nsf, ef)
}

func processMFAVerifyTask(task mfaVerifyTask) *mfaVerifyTaskResult {
	ef := genericTaskErrorFactory[mfaVerifyTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	unlockSession := lockLoginSession(task.SessionKey)
	defer unlockSession()

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	var session *LoginSession
	if s, r := getLoginSession(task.Task.Context, task.SessionKey, ef); r == nil {
		session = s
	} else {
		return r
	}

	requestLogger.Log(processingLogLevel, "processing", zap.String("sessionKey", task.SessionKey), zap.String("username", task.User), zap.String("nextStep", string(session.NextStep)))

	switch session.NextStep {
	case NextStepMFASoftwareTokenVerify:
		fallthrough
	case NextStepMFAEMailVerify:
		fallthrough
	case NextStepMFASMSVerify:
		return verifyMFACode(session, task, session.NextStep)
	}

	return ef(NewNextStepError([]NextStep{NextStepMFASoftwareTokenVerify, NextStepMFAEMailVerify, NextStepMFASMSVerify}, session.NextStep))
}

func refreshToken(ctx context.Context, token string, user string) (*cognitoTypes.AuthenticationResultType, error) {
	if useAuthToRefresh {
		input := &cognitoidentityprovider.InitiateAuthInput{
			AuthFlow: cognitoTypes.AuthFlowTypeRefreshTokenAuth,
			ClientId: aws.String(cognitoClientID),
			AuthParameters: map[string]string{
				"REFRESH_TOKEN": token,
			},
		}

		if cognitoClientSecret != "" {
			input.AuthParameters["SECRET_HASH"] = computeSecretHash(cognitoClientSecret, user, cognitoClientID)
		}

		result, err := cognitoClient.InitiateAuth(ctx, input)
		if err != nil {
			return nil, err
		}
		return result.AuthenticationResult, nil
	}

	input := &cognitoidentityprovider.GetTokensFromRefreshTokenInput{
		ClientId:     aws.String(cognitoClientID),
		RefreshToken: aws.String(token),
	}

	if cognitoClientSecret != "" {
		input.ClientSecret = aws.String(cognitoClientSecret)
	}

	result, err := cognitoClient.GetTokensFromRefreshToken(ctx, input)

	if err != nil {
		return nil, err
	}
	return result.AuthenticationResult, nil

}

func processRefreshTokenTask(task refreshTokenTask) *refreshTokenTaskResult {
	efp := func(err loginTypes.GenericError, logout bool) *refreshTokenTaskResult {
		r := &refreshTokenTaskResult{
			withResultBase: withResultBase{
				Err: err,
			},
		}
		if logout {
			r.AddSideEffect(SideEffectOutput{Type: LogOutSideEffect})
		}
		return r
	}

	ef := func(err loginTypes.GenericError) *refreshTokenTaskResult {
		return efp(err, false)
	}

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(processingLogLevel, "processing", zap.String("username", task.User))

	var token string
	if task.RefreshToken == "" {
		token = getRefreshTokenFromContext(task.Context)
	} else {
		token = task.RefreshToken
	}

	if token == "" {
		return efp(loginTypes.NewGenericAuthenticationError("no refresh token provided", "no refresh token provided", nil), false)
	}

	var user string
	if task.User == "" {
		idToken := getIdTokenFromContext(task.Context)
		if idToken == "" {
			user = ""
		} else {
			t, err := jwksValidator.ParseToken(idToken)
			if err != nil {
				requestLogger.Warn("id token is invalid, but will be used as a source of user name only", zap.Error(err))
			}
			if claims, ok := t.Claims.(jwt.MapClaims); t.Valid && ok {
				if un, ok := claims["username"].(string); ok {
					user = un
				}
			} else {
				return efp(loginTypes.NewGenericAuthenticationError("token is invalid or does not contain username", "invalid token", nil), false)
			}
		}
	} else {
		user = task.User
	}

	if user == "" {
		return efp(loginTypes.NewGenericAuthenticationError("no user provided", "no user provided", nil), true)
	}

	authResult, err := refreshToken(task.Context, token, user)

	if err != nil {
		return efp(loginTypes.NewGenericAuthenticationError("unable to refresh token", "authentication error", err), true)
	}

	if authResult != nil {
		if r := handleFinalAuthResults(task.Task.Context, authenticationResultFromCognitoType(authResult),
			task.User, task.Remember,
			genericAuthResultFactory[refreshTokenTaskResult], genericAuthErrorFactory[refreshTokenTaskResult]); r != nil {
			return r
		}
	}

	return efp(InconclusiveResponseError, false)
}

func processSatisfyPasswordUpdateRequestTask(task satisfyPasswordUpdateRequestTask) *satisfyPasswordUpdateRequestTaskResult {
	ef := genericTaskErrorFactory[satisfyPasswordUpdateRequestTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	unlockSession := lockLoginSession(task.SessionKey)
	defer unlockSession()

	requestLogger.Log(processingLogLevel, "processing", zap.String("sessionKey", task.SessionKey), zap.String("username", task.User))

	var session *LoginSession
	if s, r := getLoginSession(task.Task.Context, task.SessionKey, ef); r == nil {
		session = s
	} else {
		return r
	}

	if r := checkNextStep(session, NextStepNewPassword, ef); r != nil {
		return r
	}

	input := &cognitoidentityprovider.RespondToAuthChallengeInput{
		ChallengeName: cognitoTypes.ChallengeNameTypeNewPasswordRequired,
		ClientId:      aws.String(cognitoClientID),
		Session:       aws.String(session.CognitoSession),
		ChallengeResponses: map[string]string{
			"USERNAME":     task.User,
			"NEW_PASSWORD": task.Password,
		},
	}

	if cognitoClientSecret != "" {
		input.ChallengeResponses["SECRET_HASH"] = computeSecretHash(cognitoClientSecret, task.User, cognitoClientID)
	}

	result, err := cognitoClient.RespondToAuthChallenge(task.Context, input)
	if err != nil {
		if _, ok := errors.AsType[*cognitoTypes.PasswordHistoryPolicyViolationException](err); ok {
			return ef(loginTypes.PasswordHistoryError)
		}

		if _, ok := errors.AsType[*cognitoTypes.InvalidPasswordException](err); ok {
			return ef(loginTypes.InvalidNewPasswordError)
		}

		return ef(loginTypes.WrapWithInternalError(err))
	}

	nsf := genericNextStepFactory[satisfyPasswordUpdateRequestTaskResult]

	if result.ChallengeName == "" {
		if result.AuthenticationResult != nil {
			if r := handleAuthResults(task.Task.Context, authenticationResultFromCognitoType(result.AuthenticationResult),
				task.User, session.RememberUser, task.SessionKey,
				genericAuthResultFactory[satisfyPasswordUpdateRequestTaskResult], nsf, genericAuthErrorFactory[satisfyPasswordUpdateRequestTaskResult], requestLogger); r != nil {
				return r
			}
		}
		return ef(NoChallengeOrAuthenticationResultError)
	}

	return handleChallenge(result.ChallengeName, result.ChallengeParameters, task.Task.Context, *result.Session, task.SessionKey, session.RememberUser,
		genericNextStepFactory[satisfyPasswordUpdateRequestTaskResult], ef)
}

func processLogOutTask(task logOutTask) *logOutTaskResult {
	ef := genericTaskErrorFactory[logOutTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(processingLogLevel, "processing")

	//always report success
	go func() {
		ctx := context.WithoutCancel(context.Background())
		token := task.RefreshToken

		if token == "" {
			if msq := getMasqueradedTokenFromContext(task.Context); msq != "" {
				r, err := unmaskToken(ctx, msq, requestLogger, false, true)
				if err != nil {
					requestLogger.Warn("failed to unmask token to rewoke", zap.Error(err))
					return
				}
				dropMasqueradedToken(msq, requestLogger)
				token = r.RefreshToken
			} else if rt := getRefreshTokenFromContext(task.Context); rt != "" {
				token = rt
			} else {
				requestLogger.Warn("no token provided in body and no token to unmask")
				return
			}

		}

		input := &cognitoidentityprovider.RevokeTokenInput{
			ClientId: aws.String(cognitoClientID),
			Token:    aws.String(token),
		}

		if cognitoClientSecret != "" {
			input.ClientSecret = aws.String(cognitoClientSecret)
		}

		_, err := cognitoClient.RevokeToken(ctx, input)

		if err != nil {
			requestLogger.Warn("failed to revoke token", zap.Error(err))
		}
	}()

	r := &logOutTaskResult{}
	r.AddSideEffect(SideEffectOutput{Type: LogOutSideEffect})

	return r
}

func processUpdatePasswordTask(task updatePasswordTask) *updatePasswordTaskResult {
	ef := genericTaskErrorFactory[updatePasswordTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(processingLogLevel, "processing")

	var accessToken string
	if at, r := checkAuthContextValue(task.Task.Context, ef); r == nil {
		accessToken = at
	} else {
		return r
	}

	input := &cognitoidentityprovider.ChangePasswordInput{
		AccessToken:      aws.String(accessToken),
		PreviousPassword: aws.String(task.CurrentPassword),
		ProposedPassword: aws.String(task.NewPassword),
	}

	_, err := cognitoClient.ChangePassword(task.Context, input)

	if err != nil {
		return ef(loginTypes.WrapWithInternalError(err))

	}

	return &updatePasswordTaskResult{}
}

func getUserFromAuthToken(ctx context.Context, accessToken string) (*cognitoidentityprovider.AdminGetUserOutput, loginTypes.GenericError) {
	token, err := jwksValidator.ValidateToken(accessToken)

	var username string

	if err != nil {
		return nil, loginTypes.NewGenericAuthenticationError("jwks validation failed", "invalid token", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); token.Valid && ok {
		if un, ok := claims["username"].(string); ok {
			username = un
		}
	} else {
		return nil, loginTypes.NewGenericAuthenticationError("token is invalid or does not contain username", "invalid token", nil)
	}

	input := &cognitoidentityprovider.AdminGetUserInput{
		UserPoolId: aws.String(cognitoUserPoolID),
		Username:   aws.String(username),
	}

	result, err := cognitoClient.AdminGetUser(ctx, input)
	if err != nil {
		return nil, loginTypes.WrapWithInternalError(err)
	}

	if result == nil {
		return nil, loginTypes.NewInternalError("result is empty", nil)
	}

	return result, nil
}

func processGetMFAStatusTask(task getMFAStatusTask) *getMFAStatusTaskResult {
	ef := genericTaskErrorFactory[getMFAStatusTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(processingLogLevel, "processing")

	var accessToken string
	if at, r := checkAuthContextValue(task.Task.Context, ef); r == nil {
		accessToken = at
	} else {
		return r
	}

	result, err := getUserFromAuthToken(task.Context, accessToken)

	if err != nil {
		return ef(err)
	}

	status := &loginTypes.MFAStatus{
		MFAMethods: []string{},
	}

	if result.UserMFASettingList != nil {
		status.MFAEnabled = len(result.UserMFASettingList) > 0
		for _, mfa := range result.UserMFASettingList {
			status.MFAMethods = append(status.MFAMethods, mfa)

			if mfa == "EMAIL_OTP" {
				status.EMAILConfigured = true
			}

			if mfa == "SOFTWARE_TOKEN_MFA" {
				status.TOTPConfigured = true
			}

			if mfa == "SMS_MFA" {
				status.SMSConfigured = true
			}
		}
	} else {
		if poolDescription.MfaConfiguration == cognitoTypes.UserPoolMfaTypeOn {
			status.MFAEnabled = true
		}
	}

	if result.PreferredMfaSetting != nil {
		status.PreferredMFA = *result.PreferredMfaSetting
	}

	for _, attr := range result.UserAttributes {
		switch *attr.Name {
		case "phone_number":
			status.HasPhoneNumber = true
			status.PhoneNumber = *attr.Value
		case "phone_number_verified":
			status.PhoneVerified = *attr.Value == "true"
		}
	}

	return &getMFAStatusTaskResult{
		status: status,
	}
}

func processUpdateMFASoftwareTokenTask(task updateMFASoftwareTokenTask) *updateMFASoftwareTokenTaskResult {
	ef := genericTaskErrorFactory[updateMFASoftwareTokenTaskResult]

	var accessToken string
	if at, r := checkAuthContextValue(task.Task.Context, ef); r == nil {
		accessToken = at
	} else {
		return r
	}

	associateInput := &cognitoidentityprovider.AssociateSoftwareTokenInput{
		AccessToken: aws.String(accessToken),
	}

	associateResult, err := cognitoClient.AssociateSoftwareToken(task.Context, associateInput)
	if err != nil {
		return ef(loginTypes.WrapWithInternalError(err))
	}

	return &updateMFASoftwareTokenTaskResult{
		payload: &updateMFASoftwareTokenTaskResultPayload{
			Code: associateResult.SecretCode,
		},
	}
}

func ensureMFAAfterUpdate(ctx context.Context, accessToken string) loginTypes.GenericError {
	if poolDescription.MfaConfiguration == cognitoTypes.UserPoolMfaTypeOptional {

		softwareTokenSettings := &cognitoTypes.SoftwareTokenMfaSettingsType{
			Enabled:      true,
			PreferredMfa: false,
		}

		mfaPreferenceInput := &cognitoidentityprovider.SetUserMFAPreferenceInput{
			AccessToken:              aws.String(accessToken),
			SoftwareTokenMfaSettings: softwareTokenSettings,
		}

		_, err := cognitoClient.SetUserMFAPreference(ctx, mfaPreferenceInput)

		if err != nil {
			return loginTypes.NewInternalError("failed to enable software token MFA", err)
		}
	}
	return nil
}

func processVerifyMFAUpdateTask(task verifyMFAUpdateTask) *verifyMFAUpdateTaskResult {
	ef := genericTaskErrorFactory[verifyMFAUpdateTaskResult]

	var accessToken string
	if at, r := checkAuthContextValue(task.Task.Context, ef); r == nil {
		accessToken = at
	} else {
		return r
	}

	input := &cognitoidentityprovider.VerifySoftwareTokenInput{
		AccessToken: aws.String(accessToken),
		UserCode:    aws.String(task.Code),
		//FriendlyDeviceName: aws.String("MyDevice"), // Optional device name
	}

	result, err := cognitoClient.VerifySoftwareToken(task.Context, input)
	if err != nil {
		if _, errOk := errors.AsType[*cognitoTypes.EnableSoftwareTokenMFAException](err); errOk {
			return ef(loginTypes.InvalidMFACodeError)
		}
		return ef(loginTypes.NewGenericAuthenticationError("token verification error", "Authentication error", err))
	}

	if result.Status != cognitoTypes.VerifySoftwareTokenResponseTypeSuccess {
		return ef(InconclusiveResponseError)
	}

	if err := ensureMFAAfterUpdate(task.Context, accessToken); err != nil {
		return ef(loginTypes.NewInternalError("failed to enable software token MFA", err))
	}

	return &verifyMFAUpdateTaskResult{}
}

func processSelectMFATask(task selectMFATask) *selectMFATaskResult {
	ef := genericTaskErrorFactory[selectMFATaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(processingLogLevel, "processing")

	unlockSession := lockLoginSession(task.SessionKey)
	defer unlockSession()

	requestLogger.Log(processingLogLevel, "processing", zap.String("sessionKey", task.SessionKey), zap.String("mfaType", string(task.MFAType)))

	var session *LoginSession
	if s, r := getLoginSession(task.Task.Context, task.SessionKey, ef); r == nil {
		session = s
	} else {
		return r
	}

	if r := checkNextStep(session, NextStepMFASelect, ef); r != nil {
		return r
	}

	t, ok := reverseMFAMapping[task.MFAType]
	if !ok {
		return ef(loginTypes.NewGenericAuthenticationError("Unsupported MFA type", "Unsupported MFA type", nil))
	}

	input := &cognitoidentityprovider.RespondToAuthChallengeInput{
		ChallengeName: cognitoTypes.ChallengeNameTypeSelectMfaType,
		ClientId:      aws.String(cognitoClientID),
		Session:       aws.String(session.CognitoSession),
		ChallengeResponses: map[string]string{
			"ANSWER":   t,
			"USERNAME": task.User,
		},
	}

	if cognitoClientSecret != "" {
		input.ChallengeResponses["SECRET_HASH"] = computeSecretHash(cognitoClientSecret, task.User, cognitoClientID)
	}

	result, err := cognitoClient.RespondToAuthChallenge(task.Context, input)
	if err != nil {
		return ef(loginTypes.NewGenericAuthenticationError("auth challenge response error", "Authentication error", err))
	}

	return handleChallenge(result.ChallengeName, result.ChallengeParameters, task.Task.Context, *result.Session, task.SessionKey, session.RememberUser,
		genericNextStepFactory[selectMFATaskResult], ef)
}

func findUsersByEmail(ctx context.Context, email string) ([]cognitoTypes.UserType, loginTypes.GenericError) {
	if strings.ContainsAny(email, "\\\"'") {
		return nil, loginTypes.NewBadRequestError("invalid email address", "invalid email address", nil)
	}
	filter := fmt.Sprintf("email = \"%s\"", email)

	input := &cognitoidentityprovider.ListUsersInput{
		UserPoolId: aws.String(cognitoUserPoolID),
		Filter:     aws.String(filter),
		Limit:      aws.Int32(2),
	}

	result, err := cognitoClient.ListUsers(ctx, input)
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

func processInitiatePasswordResetTask(task initiatePasswordResetTask) *initiatePasswordResetTaskResult { //todo: only works with email. add ability to reset by user name (disabled by default)
	ef := genericTaskErrorFactory[initiatePasswordResetTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(processingLogLevel, "processing", zap.String("email", task.Email))

	defer func() {
		time.Sleep(100 * time.Millisecond) //always sleep a bit

		users, err := findUsersByEmail(context.Background(), task.Email)
		if err != nil {
			requestLogger.Error("unable to retrieve user", zap.Error(err))
			return
		}

		if len(users) > 1 {
			requestLogger.Error("found multiple users with the same email", zap.String("email", task.Email))
		} else if len(users) == 0 {
			requestLogger.Warn("attempted password recovery for non existing email", zap.String("email", task.Email))
		} else {
			token := tools.GenerateRandomString(32)
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

			resetSettings := passwordreset.GetSettings()

			if err := sessionStorage.CreateResetPasswordSession(context.Background(), token, *user.Username, email, time.Now().Add(resetSettings.ValidFor)); err != nil {
				requestLogger.Error("failed to create password reset session", zap.Error(err))
				return
			}

			resetLink := fmt.Sprintf("%s/password/reset?token=%s", config.GetURLBase(), token)

			templateData := map[string]interface{}{
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

			result, err := sesClient.SendTemplatedEmail(context.Background(), input)
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

func redirectToPasswordErrorPageIfConfigured(errorRedirectURL string) *resetPasswordTaskResult {
	if errorRedirectURL != "" {
		return &resetPasswordTaskResult{
			redirectTo: errorRedirectURL,
		}
	}
	return nil
}

func processResetPasswordTask(task resetPasswordTask) *resetPasswordTaskResult {
	ef := genericTaskErrorFactory[resetPasswordTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(processingLogLevel, "processing")

	resetSettings := passwordreset.GetSettings()

	session, err := sessionStorage.GetResetPasswordSession(task.Context, task.Token)
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

	err = sessionStorage.DropResetPasswordSession(task.Context, task.Token)
	if err != nil {
		if r := redirectToPasswordErrorPageIfConfigured(resetSettings.ErrorRedirectURL); r != nil {
			return r
		}
		return ef(loginTypes.NewInternalError("failed to drop password reset session", err))
	}

	input := &cognitoidentityprovider.ForgotPasswordInput{
		ClientId: aws.String(cognitoClientID),
		Username: aws.String(session.User),
	}

	if cognitoClientSecret != "" {
		input.SecretHash = aws.String(computeSecretHash(cognitoClientSecret, session.User, cognitoClientID))
	}

	result, err := cognitoClient.ForgotPassword(task.Context, input)

	if err != nil {
		if r := redirectToPasswordErrorPageIfConfigured(resetSettings.ErrorRedirectURL); r != nil {
			return r
		}
		return ef(loginTypes.NewInternalError("no password error redirect configured", err))
	}

	token := tools.GenerateRandomString(32)

	if err := sessionStorage.CreateConfirmPasswordResetSession(task.Context, token, session.User, time.Now().Add(resetSettings.ValidFor)); err != nil {
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

func processFinalizePasswordResetTask(task finalizePasswordResetTask) *finalizePasswordResetTaskResult {
	ef := genericTaskErrorFactory[finalizePasswordResetTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(processingLogLevel, "processing")

	session, err := sessionStorage.GetConfirmPasswordResetSession(task.Context, task.Token)
	if err != nil {
		requestLogger.Error("failed to retrieve confirm password reset session", zap.Error(err))
		//hide any actual errors from user
		return ef(loginTypes.InvalidVerificationCodeError)
	}

	requestLogger.Log(processingLogLevel, "resetting password", zap.String("user", session.User))

	input := &cognitoidentityprovider.ConfirmForgotPasswordInput{
		ClientId:         aws.String(cognitoClientID),
		Username:         aws.String(session.User),
		ConfirmationCode: aws.String(task.Code),
		Password:         aws.String(task.Password),
	}

	if cognitoClientSecret != "" {
		input.SecretHash = aws.String(computeSecretHash(cognitoClientSecret, session.User, cognitoClientID))
	}

	_, err = cognitoClient.ConfirmForgotPassword(task.Context, input)

	if err != nil {
		if _, ok := errors.AsType[*cognitoTypes.CodeMismatchException](err); ok {
			return ef(loginTypes.InvalidVerificationCodeError)
		}

		return ef(loginTypes.NewInternalError("unable to finalize password reset", err))
	}

	requestLogger.Info("user finalized password reset",
		zap.String("user", session.User),
	)

	err = sessionStorage.DropConfirmPasswordResetSession(context.Background(), task.Token)
	if err != nil {
		//no point returning an error here - actual reset is complete
		requestLogger.Error("failed to drop confirm-password-reset session", zap.Error(err))
	}

	return &finalizePasswordResetTaskResult{}
}

func dropMasqueradedToken(token string, requestLogger *zap.Logger) {
	err := masquerade.GetStorage().DropMasqueradedRecord(context.Background(), token)
	if err != nil {
		requestLogger.Error("failed to drop masqueraded token", zap.Error(err))
	}
}

func unmaskToken(ctx context.Context, token string, requestLogger *zap.Logger, refreshExpired bool, appendRefreshToken bool) (*loginTypes.AuthTokenSet, loginTypes.GenericError) {
	if token == "" {
		return nil, loginTypes.UnauthorizedError
	}

	d, err := masquerade.GetStorage().GetMasqueradedRecord(ctx, token)
	if err != nil {
		return nil, loginTypes.NewInternalError("unable to unmask token", err)
	}

	if d == nil {
		return nil, loginTypes.InvalidTokenMaskError
	}

	if refreshExpired {
		deadline := time.Now().Add(10 * time.Second)
		refreshRequired := false

		if !d.Tokens[loginTypes.AuthTokenType].Expires.After(deadline) {
			refreshRequired = true
		}

		if !d.Tokens[loginTypes.IDTokenType].Expires.After(deadline) {
			refreshRequired = true
		}

		//if at, ok := d.Tokens[loginTypes.AuthTokenType]; ok {
		//	if err := validateTokenOrigin(at.Value); err != nil {
		//		go func() {
		//			requestLogger.Error("auth token is invalid; removing masqueraded record", zap.Error(err))
		//			if err := masquerade.GetStorage().DropMasqueradedRecord(context.Background(), token); err != nil {
		//				requestLogger.Error("failed to drop masqueraded token", zap.Error(err))
		//			}
		//		}()
		//
		//		return nil, err
		//	}
		//} else {
		//	requestLogger.Warn("token set has no auth token - skipping pool check")
		//}

		if refreshRequired {
			requestLogger.Log(processingLogLevel, "refresh required")

			if rt, ok := d.Tokens[loginTypes.RefreshTokenType]; ok {
				var ttl time.Duration
				if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
					ttl = deadline.Sub(time.Now())
				} else {
					ttl = 60 * time.Second
				}

				ro := locking.GetReturnOnce[*cognitoTypes.AuthenticationResultType](token, ttl)
				authResults, err := ro.Do(ctx, func(ctx context.Context) (*cognitoTypes.AuthenticationResultType, error) {
					return refreshToken(ctx, rt.Value, d.User)
				})

				if err != nil {
					dropMasqueradedToken(token, requestLogger)
					return nil, loginTypes.NewGenericAuthenticationError("unable to refresh token", "authentication error", err)
				}

				r, err := authResultToAuthTokenSet(authenticationResultFromCognitoType(authResults))
				if err != nil {
					dropMasqueradedToken(token, requestLogger)
					return nil, loginTypes.NewGenericAuthenticationError("unable to convert auth result to token set", "authentication error", err)
				}

				return r, nil
			}
			return nil, loginTypes.NewGenericAuthenticationError("unable to refresh tokens - no refresh token", "unauthorized", nil)
		}
	}

	return tokenSetToAuthPayload(d.Tokens, appendRefreshToken), nil
}

func processUnmaskTokenTask(task unmaskTokenTask) *unmaskTokenTaskResult {
	if r := checkTaskContext(task.Task, genericTaskErrorFactory[unmaskTokenTaskResult]); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)
	requestLogger.Log(processingLogLevel, "processing")

	r, err := unmaskToken(task.Context, task.Token, requestLogger, true, masquerade.UnmaskRefreshToken())

	if err != nil {
		return genericTaskErrorFactory[unmaskTokenTaskResult](err)
	}

	return &unmaskTokenTaskResult{
		tokenSet: r,
	}
}

func cognitoIdTokenToProfile(token string) (*UserIdTokenProfile, error) {
	t, err := jwksValidator.ValidateToken(token)
	if err != nil {
		return nil, err
	}

	claimsMap, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token")
	}

	var groups []string

	if g, ok := claimsMap["cognito:groups"].([]interface{}); ok {
		for _, gn := range g {
			if gn, ok := gn.(string); ok {
				groups = append(groups, gn)
			}
		}
	}

	username := "unknown"
	if u, ok := claimsMap["cognito:username"]; ok {
		username = u.(string)
	}

	email := "unknown"
	if e, ok := claimsMap["email"]; ok {
		email = e.(string)
	}

	emailVerified := false
	if v, ok := claimsMap["email_verified"]; ok {
		emailVerified = v.(bool)
	}

	r := &UserIdTokenProfile{
		Groups:        groups,
		Username:      username,
		Email:         email,
		EmailVerified: emailVerified,
	}

	return r, nil
}

func processGetProfileTask(task getProfileTask) *getProfileTaskResult {
	ef := genericTaskErrorFactory[getProfileTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(processingLogLevel, "processing")

	var idToken string

	if msq := getMasqueradedTokenFromContext(task.Context); msq == "" {
		if _, r := checkAuthContextValue(task.Task.Context, ef); r != nil {
			return r
		}
		idToken = getIdTokenFromContext(task.Context)
	} else {
		r, err := unmaskToken(task.Context, msq, requestLogger, true, masquerade.UnmaskRefreshToken())

		if err != nil {
			return ef(err)
		}

		if r := checkAuthToken(r.AccessToken, ef); r != nil {
			return r
		}

		idToken = r.IdToken
	}

	if idToken == "" {
		return ef(loginTypes.NewBadRequestError("no id token provided", "no id token provided", nil))
	}

	t, jwksErr := cognitoIdTokenToProfile(idToken)
	if jwksErr != nil {
		return ef(loginTypes.NewInternalError("jwks error", jwksErr))
	}

	return &getProfileTaskResult{
		Profile: t,
	}
}

func processValidateTask(task tokenValidationTask) *tokenValidationTaskResult {
	ef := genericTaskErrorFactory[tokenValidationTaskResult]

	if r := checkTaskContext(task.Task, ef); r != nil {
		return r
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(processingLogLevel, "processing")

	validity := map[string]bool{}
	validationError := map[string]string{}

	for tokenName, token := range task.Tokens {
		_, err := jwksValidator.ValidateToken(token)
		if err == nil {
			validity[tokenName] = true
		} else {
			validity[tokenName] = false
			validationError[tokenName] = err.Error()
		}
	}

	return &tokenValidationTaskResult{
		Validity:         validity,
		ValidationErrors: validationError,
	}
}
