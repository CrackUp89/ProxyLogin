package cognito

import (
	"context"
	"errors"
	"fmt"
	"proxylogin/internal/manager/login/masquerade"
	loginTypes "proxylogin/internal/manager/login/types"
	"slices"
	"strings"
	"time"

	cognitoTypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"go.uber.org/zap"
)

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

func (c *Cognito) authResultToAuthTokenSet(authResult *AuthenticationResult) (*loginTypes.AuthTokenSet, error) {
	result := loginTypes.AuthTokenSet{
		AccessToken: *authResult.AccessToken,
		IdToken:     *authResult.IdToken,
	}

	if authToken, err := c.jwksValidator.ParseToken(*authResult.AccessToken); err == nil {
		if authExpires, err := authToken.Claims.GetExpirationTime(); err == nil {
			result.AccessTokenExpires = &authExpires.Time
		}
	} else {
		return nil, err
	}

	if idToken, err := c.jwksValidator.ParseToken(*authResult.IdToken); err == nil {
		if authExpires, err := idToken.Claims.GetExpirationTime(); err == nil {
			result.IdTokenExpires = &authExpires.Time
		}
	} else {
		return nil, err
	}

	if authResult.RefreshToken != nil {
		result.RefreshToken = *authResult.RefreshToken
		var expiryDuration time.Duration
		if c.poolClientDescription.TokenValidityUnits == nil {
			expiryDuration = getDurationFromTokenValidity(c.poolClientDescription.RefreshTokenValidity, cognitoTypes.TimeUnitsTypeDays)
		} else {
			expiryDuration = getDurationFromTokenValidity(c.poolClientDescription.RefreshTokenValidity, c.poolClientDescription.TokenValidityUnits.RefreshToken)
		}
		result.RefreshTokenExpires = new(time.Now().Add(expiryDuration))
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

func (c *Cognito) authResultToMasqueradedToken(ctx context.Context, authResult *AuthenticationResult, user string) (*loginTypes.MasqueradedToken, error) {
	key, err := c.masq.GetNewKey(ctx)
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

	if authToken, err := c.jwksValidator.ParseToken(*authResult.AccessToken); err == nil {
		if tokenExpires, err := authToken.Claims.GetExpirationTime(); err == nil {
			authTokenRecord.Expires = tokenExpires.Time
			if tokenExpires.Time.After(expires) {
				expires = tokenExpires.Time
			}
		}
	} else {
		return nil, err
	}

	if idToken, err := c.jwksValidator.ParseToken(*authResult.IdToken); err == nil {
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
		if c.poolClientDescription.TokenValidityUnits == nil {
			expiryDuration = getDurationFromTokenValidity(c.poolClientDescription.RefreshTokenValidity, cognitoTypes.TimeUnitsTypeDays)
		} else {
			expiryDuration = getDurationFromTokenValidity(c.poolClientDescription.RefreshTokenValidity, c.poolClientDescription.TokenValidityUnits.RefreshToken)
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

	err = c.masq.Storage().StoreMasqueradedRecord(ctx, key, mr, expires)
	if err != nil {
		return nil, err
	}

	return &loginTypes.MasqueradedToken{
		Token:        key,
		TokenExpires: expires,
	}, nil
}

func (c *Cognito) authResultToPayload(ctx context.Context, authResult *AuthenticationResult, user string) (AuthResultsData, error) {
	if c.appConfig.UseCookies && c.appConfig.Masquerade {
		return c.authResultToMasqueradedToken(ctx, authResult, user)
	}
	return c.authResultToAuthTokenSet(authResult)
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
}](c *Cognito, ctx context.Context, csrfToken, loginSessionId string, authResults *AuthenticationResult, rememberUser bool,
	nsf nextStepFactory[R, PR], ef authErrorFactory[R, PR], logger *zap.Logger) PR {
	if c.poolDescription.MfaConfiguration == cognitoTypes.UserPoolMfaTypeOff {
		logger.Error("unable to enforce mfa - MFA is disabled in the User Pool configuration")
		return nil
	}

	if c.poolDescription.MfaConfiguration == cognitoTypes.UserPoolMfaTypeOptional {

		result, er := c.getUserFromAuthToken(ctx, *authResults.AccessToken)

		if er != nil {
			return ef(er, false)
		}

		if result.UserMFASettingList != nil && len(result.UserMFASettingList) > 0 {
			return nil
		}

		nextStep := NextStepMFASetup

		availableMethods := make([]string, 0, 3)

		if c.userPoolMFAConfig.EmailMfaConfiguration != nil {
			availableMethods = append(availableMethods, "email")
		}

		if c.userPoolMFAConfig.SoftwareTokenMfaConfiguration != nil && c.userPoolMFAConfig.SoftwareTokenMfaConfiguration.Enabled {
			availableMethods = append(availableMethods, "software_token")
		}

		//TODO: find a better way to detect if SMS is configured
		if c.userPoolMFAConfig.SmsMfaConfiguration != nil && c.userPoolMFAConfig.SmsMfaConfiguration.SmsAuthenticationMessage != nil {
			availableMethods = append(availableMethods, "sms")
		}

		if len(availableMethods) == 0 {
			return ef(loginTypes.NewInternalError("no MFA methods available to setup for user", nil), false)
		}

		expires := time.Now().Add(c.loginSessionValidFor)

		if err := c.sessionStorage.CreateMFAEnforcementSession(ctx, loginSessionId, rememberUser, authResults, expires); err != nil {
			return ef(loginTypes.NewInternalError("failed to create MFA enforcement session", err), false)
		}

		if err := c.sessionStorage.CreateLoginSession(ctx, csrfToken, loginSessionId, "",
			nextStep, NextStepVariantMFAEnforcement, rememberUser, expires, nil); err != nil {
			return ef(loginTypes.NewInternalError("failed to create login session", err), false)
		}

		nls := &NextLoginStep{
			LoginSessionId: loginSessionId,
			NextStep:       nextStep,
		}

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
}](c *Cognito, ctx context.Context, authResults *AuthenticationResult, user string, remember bool,
	rf authResultsFactory[R, PR], ef authErrorFactory[R, PR]) PR {

	authPayload, err := c.authResultToPayload(ctx, authResults, user)
	return handleAuthPayload(authPayload, remember, err, rf, ef)
}

func handleAuthResults[R any, PR interface {
	*R
	WithTaskResultBase
}](c *Cognito, ctx context.Context, authResults *AuthenticationResult, user string, remember bool,
	csrfToken,
	loginSessionId string,
	rf authResultsFactory[R, PR], nsf nextStepFactory[R, PR], ef authErrorFactory[R, PR], logger *zap.Logger) PR {

	if c.cfg.EnforceMFA {
		if r := enforceMFAAfterAuth(c, ctx, csrfToken, loginSessionId, authResults, remember, nsf, ef, logger); r != nil {
			return r
		}
	}

	return handleFinalAuthResults(c, ctx, authResults, user, remember, rf, ef)
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
		AccessTokenExpires: new(tokenSet[loginTypes.AuthTokenType].Expires),
		IdToken:            tokenSet[loginTypes.IDTokenType].Value,
		IdTokenExpires:     new(tokenSet[loginTypes.IDTokenType].Expires),
	}
	if appendRefreshToken {
		if s, ok := tokenSet[loginTypes.RefreshTokenType]; ok {
			r.RefreshToken = s.Value
			r.RefreshTokenExpires = new(s.Expires)
		}
	}
	return r
}

func handleChallenge[R any, PR interface {
	*R
	WithTaskResultBase
}](c *Cognito, challenge cognitoTypes.ChallengeNameType, challengeParameters map[string]string,
	ctx context.Context, cognitoSession string, csrfToken, loginSessionId string, rememberUser bool,
	rf nextStepFactory[R, PR],
	ef errorFactory[R, PR]) PR {

	if challenge == "" {
		return ef(loginTypes.NewInternalError("challenge is empty", nil))
	}

	nls := &NextLoginStep{
		LoginSessionId: loginSessionId,
	}

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

	if err := c.sessionStorage.CreateLoginSession(ctx, csrfToken, loginSessionId, cognitoSession, nextStep, NextStepVariantDefault, rememberUser, time.Now().Add(c.loginSessionValidFor), sessionTag); err != nil {
		return ef(loginTypes.NewInternalError("failed to create login session", err))
	}

	nls.NextStep = nextStep

	return rf(nls)
}

func getLoginSession[R any, PR interface {
	*R
	WithTaskResultBase
}](c *Cognito, ctx context.Context, loginSessionId string, ef errorFactory[R, PR]) (*LoginSession, PR) {
	session, err := c.sessionStorage.GetLoginSession(ctx, loginSessionId)
	if err != nil {
		return nil, ef(loginTypes.NewInternalError("failed to retrieve login session", err))
	}
	if session == nil {
		return nil, ef(loginTypes.GenericLoginSessionExpiredOrDoesNotExistError)
	}
	return session, nil
}

func getMFAEnforcementSession[R any, PR interface {
	*R
	WithTaskResultBase
}](c *Cognito, ctx context.Context, loginSessionId string, ef errorFactory[R, PR]) (*MFAEnforcementSession, PR) {
	session, err := c.sessionStorage.GetMFAEnforcementSession(ctx, loginSessionId)
	if err != nil {
		return nil, ef(loginTypes.NewInternalError("failed to retrieve MFA enforcement session", err))
	}
	if session == nil {
		return nil, ef(loginTypes.GenericLoginSessionExpiredOrDoesNotExistError)
	}
	return session, nil
}

func checkNextStep[R any, PR interface {
	*R
	WithTaskResultBase
}](s *LoginSession, ef errorFactory[R, PR], expectedSteps ...NextStep) PR {
	if !slices.Contains(expectedSteps, s.NextStep) {
		return ef(loginTypes.NewBadRequestError(fmt.Sprintf("unexpected next step: %s; expected: %v", s.NextStep, expectedSteps), "unexpected next step", loginTypes.DefaultBadRequestCode, nil))
	}
	return nil
}

func (c *Cognito) dropLoginSession(ctx context.Context, loginSessionId string) error {
	return c.sessionStorage.DropLoginSession(ctx, loginSessionId)
}

func (c *Cognito) dropMFAEnforcementSession(ctx context.Context, loginSessionId string) error {
	return c.sessionStorage.DropMFAEnforcementSession(ctx, loginSessionId)
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
