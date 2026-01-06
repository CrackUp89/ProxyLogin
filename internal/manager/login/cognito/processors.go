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
	"proxylogin/internal/manager/login/passwordreset"
	loginTypes "proxylogin/internal/manager/login/types"
	"proxylogin/internal/manager/tools"
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

func authResultToTokenSet(authResult *cognitoTypes.AuthenticationResultType) loginTypes.TokenSet {
	result := loginTypes.TokenSet{
		AccessToken: *authResult.AccessToken,
		IdToken:     *authResult.IdToken,
	}
	if authResult.RefreshToken != nil {
		result.RefreshToken = *authResult.RefreshToken
	}
	return result
}

func handleChallenge(challenge cognitoTypes.ChallengeNameType, challengeParameters map[string]string, task Task, cognitoSessions string) {

	if challenge == "" {
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewInternalError("challenge is empty", nil),
		}
		return
	}

	tr := TaskResult{
		SessionKey: task.SessionKey,
	}

	var sessionTag interface{} = nil
	var nextStep NextStep

	switch challenge {
	case cognitoTypes.ChallengeNameTypeSelectMfaType:
		nextStep = NextStepMFASelect
		v, ok := challengeParameters["MFAS_CAN_CHOOSE"]
		if ok {
			tr.Payload = map[string]interface{}{
				"available_mfa_methods": mapMFAList(strings.Split(strings.Trim(v, "[]"), ",")),
			}
		} else {
			task.ResultChan <- TaskResult{
				Err: loginTypes.NewInternalError("no MFA methods available for user login", nil),
			}
			return
		}
		break
	case cognitoTypes.ChallengeNameTypeMfaSetup:
		nextStep = NextStepMFASetup
		v, ok := challengeParameters["MFAS_CAN_SETUP"]
		if ok {
			tr.Payload = map[string]interface{}{
				"available_mfa_methods": mapMFAList(strings.Split(strings.Trim(v, "[]"), ",")),
			}
		} else {
			task.ResultChan <- TaskResult{
				Err: loginTypes.NewInternalError("no MFA methods available to setup for user", nil),
			}
			return
		}
		break
	case cognitoTypes.ChallengeNameTypeSoftwareTokenMfa:
		nextStep = NextStepMFASoftwareTokenVerify
		break
	case cognitoTypes.ChallengeNameTypeEmailOtp:
		nextStep = NextStepMFAEMailVerify
		break
	case cognitoTypes.ChallengeNameTypeSmsMfa:
		nextStep = NextStepMFAEMailVerify
		break
	case cognitoTypes.ChallengeNameTypeNewPasswordRequired:
		nextStep = NextStepNewPassword
		v, ok := challengeParameters["requiredAttributes"]
		if ok {
			tr.Payload = map[string]interface{}{
				"required": v,
			}
			sessionTag = v
		}
		break
	default:
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewInternalError("unsupported challenge type: "+string(challenge), nil),
		}
		return
	}

	if err := sessionStorage.CreateLoginSession(task.Context, task.SessionKey, cognitoSessions, nextStep, time.Now().Add(loginSessionValidFor), sessionTag); err != nil {
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewInternalError("failed to create login session", err),
		}
		return
	}

	tr.NextStep = nextStep
	task.ResultChan <- tr
}

func getLoginSession(t Task) *LoginSession {
	session, err := sessionStorage.GetLoginSession(t.Context, t.SessionKey)
	if err != nil {
		t.ResultChan <- TaskResult{
			Err: loginTypes.NewInternalError("failed to retrieve login session", err),
		}
		return nil
	}
	if session == nil {
		t.ResultChan <- TaskResult{
			Err: loginTypes.NewLoginSessionExpiredOrDoesNotExistError(),
		}
		return nil
	}
	return session
}

func checkNextStep(t Task, s *LoginSession, expectedStep NextStep) bool {
	if s.NextStep != expectedStep {
		t.ResultChan <- TaskResult{
			Err: loginTypes.NewBadRequestError(fmt.Sprintf("unexpected next step: %s; expected: %s", s.NextStep, expectedStep), "unexpected next step", nil),
		}
		return false
	}
	return true
}

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

func checkTaskContext(t Task) bool {
	if err := t.Context.Err(); err != nil {
		t.ResultChan <- TaskResult{
			Err: loginTypes.NewInternalError(err.Error(), err),
		}
		return false
	}
	return true
}

func getRequestLoggerFromTask(task Task) *zap.Logger {
	return getRequestLogger(task.Context).Named("processors")
}

func processLoginTask(task loginTask) {
	if !checkTaskContext(task.Task) {
		return
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
		var unf *cognitoTypes.UserNotFoundException
		var ip *cognitoTypes.NotAuthorizedException
		if errors.As(err, &unf) || errors.As(err, &ip) {
			task.ResultChan <- TaskResult{
				Err: loginTypes.InvalidUserOrPasswordError,
			}
			return
		}

		task.ResultChan <- TaskResult{
			Err: loginTypes.NewInternalError(err.Error(), err),
		}
		return
	}

	if result.ChallengeName == "" {
		if result.AuthenticationResult != nil {
			task.ResultChan <- TaskResult{
				Payload: authResultToTokenSet(result.AuthenticationResult),
			}
			return
		} else {
			task.ResultChan <- TaskResult{
				Err: NoChallengeOrAuthenticationResultError,
			}
			return
		}
	}

	handleChallenge(result.ChallengeName, result.ChallengeParameters, task.Task, *result.Session)
}

func processMFASetupTask(task mfaSetupTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	unlockSession := lockLoginSession(task.SessionKey)
	defer unlockSession()

	requestLogger.Log(processingLogLevel, "processing", zap.String("sessionKey", task.SessionKey), zap.String("username", task.User))

	session := getLoginSession(task.Task)

	if session == nil || !checkNextStep(task.Task, session, NextStepMFASetup) {
		return
	}

	switch task.MFAType {
	case loginTypes.MFATypeSoftwareToken:

		associateInput := &cognitoidentityprovider.AssociateSoftwareTokenInput{
			Session: aws.String(session.CognitoSession),
		}

		associateResult, err := cognitoClient.AssociateSoftwareToken(task.Context, associateInput)
		if err != nil {
			task.ResultChan <- TaskResult{
				Err: loginTypes.WrapWithInternalError(err),
			}
			return
		}

		if err := sessionStorage.CreateLoginSession(task.Context, task.SessionKey, *associateResult.Session, NextStepMFASoftwareTokenSetupVerify, time.Now().Add(loginSessionValidFor), nil); err != nil {
			task.ResultChan <- TaskResult{
				Err: loginTypes.NewInternalError("failed to create login session", err),
			}
			return
		}

		task.ResultChan <- TaskResult{
			NextStep:   NextStepMFASoftwareTokenSetupVerify,
			SessionKey: task.SessionKey,
			Payload:    associateResult.SecretCode,
		}
		return
	}

	task.ResultChan <- TaskResult{
		Err: loginTypes.NewBadRequestError("unsupported MFA setup type", "unsupported MFA setup type", nil),
	}
}

func processMFASetupVerifySoftwareTokenTask(task mfaSetupVerifySoftwareTokenTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	unlockSession := lockLoginSession(task.SessionKey)
	defer unlockSession()

	requestLogger.Log(processingLogLevel, "processing", zap.String("sessionKey", task.SessionKey), zap.String("username", task.User))

	session := getLoginSession(task.Task)
	if session == nil || !checkNextStep(task.Task, session, NextStepMFASoftwareTokenSetupVerify) {
		return
	}

	verifyInput := &cognitoidentityprovider.VerifySoftwareTokenInput{
		Session:  aws.String(session.CognitoSession),
		UserCode: aws.String(task.Code),
		//FriendlyDeviceName: aws.String("MyDevice"), // Optional device name
	}

	verifyResult, err := cognitoClient.VerifySoftwareToken(task.Context, verifyInput)
	if err != nil {
		var est *cognitoTypes.EnableSoftwareTokenMFAException
		if errors.As(err, &est) {
			task.ResultChan <- TaskResult{
				Err: loginTypes.InvalidMFACodeError,
			}
			return
		}
		task.ResultChan <- TaskResult{
			Err: loginTypes.WrapWithInternalError(err),
		}
		return
	}

	if verifyResult.Status != cognitoTypes.VerifySoftwareTokenResponseTypeSuccess {
		task.ResultChan <- TaskResult{
			Err: InconclusiveResponseError,
		}
		return
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
		task.ResultChan <- TaskResult{
			Err: loginTypes.WrapWithInternalError(err),
		}
		return
	}

	if finalResult.AuthenticationResult != nil {
		task.ResultChan <- TaskResult{
			Payload: authResultToTokenSet(finalResult.AuthenticationResult),
		}
		return
	}

	handleChallenge(finalResult.ChallengeName, finalResult.ChallengeParameters, task.Task, *finalResult.Session)
}

func verifyMFACode(session *LoginSession, task mfaVerifyTask, step NextStep) {
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
		task.ResultChan <- TaskResult{
			Err: loginTypes.WrapWithInternalError(err),
		}
		return
	}

	if result.ChallengeName == "" {
		if result.AuthenticationResult != nil {
			task.ResultChan <- TaskResult{
				Payload: authResultToTokenSet(result.AuthenticationResult),
			}
			return
		} else {
			task.ResultChan <- TaskResult{
				Err: NoChallengeOrAuthenticationResultError,
			}
			return
		}
	}

	handleChallenge(result.ChallengeName, result.ChallengeParameters, task.Task, *result.Session)
}

func processMFAVerifyTask(task mfaVerifyTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	unlockSession := lockLoginSession(task.SessionKey)
	defer unlockSession()

	if !checkTaskContext(task.Task) {
		return
	}

	session := getLoginSession(task.Task)
	if session == nil {
		return
	}

	requestLogger.Log(processingLogLevel, "processing", zap.String("sessionKey", task.SessionKey), zap.String("username", task.User), zap.String("nextStep", string(session.NextStep)))

	switch session.NextStep {
	case NextStepMFASoftwareTokenVerify:
		fallthrough
	case NextStepMFAEMailVerify:
		fallthrough
	case NextStepMFASMSVerify:
		verifyMFACode(session, task, session.NextStep)
	}
	task.ResultChan <- TaskResult{
		Err: NewNextStepError([]NextStep{NextStepMFASoftwareTokenVerify, NextStepMFAEMailVerify, NextStepMFASMSVerify}, session.NextStep),
	}
}

func processRefreshTokenTask(task refreshTokenTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	var err error
	var authResult *cognitoTypes.AuthenticationResultType

	requestLogger.Log(processingLogLevel, "processing", zap.String("username", task.User))

	if useAuthToRefresh {
		input := &cognitoidentityprovider.InitiateAuthInput{
			AuthFlow: cognitoTypes.AuthFlowTypeRefreshTokenAuth,
			ClientId: aws.String(cognitoClientID),
			AuthParameters: map[string]string{
				"REFRESH_TOKEN": task.RefreshToken,
			},
		}

		if cognitoClientSecret != "" {
			input.AuthParameters["SECRET_HASH"] = computeSecretHash(cognitoClientSecret, task.User, cognitoClientID)
		}

		var result *cognitoidentityprovider.InitiateAuthOutput
		result, err = cognitoClient.InitiateAuth(task.Context, input)
		if err == nil {
			authResult = result.AuthenticationResult
		}
	} else {
		input := &cognitoidentityprovider.GetTokensFromRefreshTokenInput{
			ClientId:     aws.String(cognitoClientID),
			RefreshToken: aws.String(task.RefreshToken),
		}

		if cognitoClientSecret != "" {
			input.ClientSecret = aws.String(cognitoClientSecret)
		}

		var result *cognitoidentityprovider.GetTokensFromRefreshTokenOutput
		result, err = cognitoClient.GetTokensFromRefreshToken(task.Context, input)

		if err == nil {
			authResult = result.AuthenticationResult
		}
	}

	if err != nil {
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError(err.Error(), "authentication error", err),
		}
		return
	}

	if authResult != nil {
		task.ResultChan <- TaskResult{
			Payload: authResultToTokenSet(authResult),
		}
		return
	}

	task.ResultChan <- TaskResult{
		Err: InconclusiveResponseError,
	}
}

func processSatisfyPasswordUpdateRequestTask(task satisfyPasswordUpdateRequestTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	unlockSession := lockLoginSession(task.SessionKey)
	defer unlockSession()

	requestLogger.Log(processingLogLevel, "processing", zap.String("sessionKey", task.SessionKey), zap.String("username", task.User))

	session := getLoginSession(task.Task)
	if session == nil || !checkNextStep(task.Task, session, NextStepNewPassword) {
		return
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
		var pv *cognitoTypes.PasswordHistoryPolicyViolationException
		if errors.As(err, &pv) {
			task.ResultChan <- TaskResult{
				Err: loginTypes.PasswordHistoryError,
			}
			return
		}

		var ip *cognitoTypes.InvalidPasswordException
		if errors.As(err, &ip) {
			task.ResultChan <- TaskResult{
				Err: loginTypes.InvalidNewPasswordError,
			}
			return
		}

		task.ResultChan <- TaskResult{
			Err: loginTypes.WrapWithInternalError(err),
		}
		return
	}

	if result.ChallengeName == "" {
		if result.AuthenticationResult != nil {
			task.ResultChan <- TaskResult{
				Payload: authResultToTokenSet(result.AuthenticationResult),
			}
			return
		} else {
			task.ResultChan <- TaskResult{
				Err: NoChallengeOrAuthenticationResultError,
			}
			return
		}
	}

	handleChallenge(result.ChallengeName, result.ChallengeParameters, task.Task, *result.Session)
}

func processLogOutTask(task logOutTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(processingLogLevel, "processing")

	//always report success
	go func() {
		input := &cognitoidentityprovider.RevokeTokenInput{
			ClientId: aws.String(cognitoClientID),
			Token:    aws.String(task.RefreshToken),
		}

		if cognitoClientSecret != "" {
			input.ClientSecret = aws.String(cognitoClientSecret)
		}

		_, err := cognitoClient.RevokeToken(context.Background(), input)

		if err != nil {
			requestLogger.Warn("failed to revoke token", zap.Error(err))
		}
	}()

	task.ResultChan <- TaskResult{}
}

func processUpdatePasswordTask(task updatePasswordTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(processingLogLevel, "processing")

	_, err := jwksValidator.ValidateToken(task.AccessToken)

	if err != nil {
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError(err.Error(), "invalid token", err),
		}
		return
	}

	input := &cognitoidentityprovider.ChangePasswordInput{
		AccessToken:      aws.String(task.AccessToken),
		PreviousPassword: aws.String(task.CurrentPassword),
		ProposedPassword: aws.String(task.NewPassword),
	}

	_, err = cognitoClient.ChangePassword(task.Context, input)

	if err != nil {
		task.ResultChan <- TaskResult{
			Err: loginTypes.WrapWithInternalError(err),
		}
		return
	}

	task.ResultChan <- TaskResult{}
}

func processGetMFAStatusTask(task getMFAStatusTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(processingLogLevel, "processing")

	token, err := jwksValidator.ValidateToken(task.AccessToken)

	var username string

	if err != nil {
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError(err.Error(), "invalid token", err),
		}
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); token.Valid && ok {
		if un, ok := claims["username"].(string); ok {
			username = un
		}
	} else {
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError("token is invalid or does not contain username", "invalid token", nil),
		}
		return
	}

	input := &cognitoidentityprovider.AdminGetUserInput{
		UserPoolId: aws.String(cognitoUserPoolID),
		Username:   aws.String(username),
	}

	result, err := cognitoClient.AdminGetUser(context.TODO(), input)

	if err != nil {
		task.ResultChan <- TaskResult{
			Err: loginTypes.WrapWithInternalError(err),
		}
		return
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

	task.ResultChan <- TaskResult{
		Payload: status,
	}
}

func updateSoftwareToken(task updateMFASoftwareTokenTask) {
	associateInput := &cognitoidentityprovider.AssociateSoftwareTokenInput{
		AccessToken: aws.String(task.AccessToken),
	}

	associateResult, err := cognitoClient.AssociateSoftwareToken(context.TODO(), associateInput)
	if err != nil {
		task.ResultChan <- TaskResult{
			Err: loginTypes.WrapWithInternalError(err),
		}
		return
	}

	if err = sessionStorage.CreateLoginSession(task.Context, task.SessionKey, "", NextStepMFASoftwareTokenSetupVerify, time.Now().Add(loginSessionValidFor), nil); err != nil {
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewInternalError("failed to create login session", err),
		}
		return
	}

	task.ResultChan <- TaskResult{
		NextStep:   NextStepMFASoftwareTokenSetupVerify,
		SessionKey: task.SessionKey,
		Payload:    associateResult.SecretCode,
	}
}

func processUpdateMFATask(task updateMFASoftwareTokenTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(processingLogLevel, "processing", zap.String("mfaType", string(task.MFAType)))

	switch task.MFAType {
	case loginTypes.MFATypeSoftwareToken:
		updateSoftwareToken(task)
		return
	default:
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewBadRequestError("MFA method not supported", "MFA method not supported", nil),
		}
		return
	}

}

func verifyMFASetupSoftwareToken(task verifyMFAUpdateTask) {
	input := &cognitoidentityprovider.VerifySoftwareTokenInput{
		AccessToken: aws.String(task.AccessToken),
		UserCode:    aws.String(task.Code),
		//FriendlyDeviceName: aws.String("MyDevice"), // Optional device name
	}

	result, err := cognitoClient.VerifySoftwareToken(task.Context, input)
	if err != nil {
		var est *cognitoTypes.EnableSoftwareTokenMFAException
		if errors.As(err, &est) {
			task.ResultChan <- TaskResult{
				Err: loginTypes.InvalidMFACodeError,
			}
			return
		}
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError(err.Error(), "Authentication error", err),
		}
		return
	}

	if result.Status != cognitoTypes.VerifySoftwareTokenResponseTypeSuccess {
		task.ResultChan <- TaskResult{
			Err: InconclusiveResponseError,
		}
		return
	}

	if poolDescription.MfaConfiguration == cognitoTypes.UserPoolMfaTypeOptional {

		softwareTokenSettings := &cognitoTypes.SoftwareTokenMfaSettingsType{
			Enabled:      true,
			PreferredMfa: false,
		}

		mfaPreferenceInput := &cognitoidentityprovider.SetUserMFAPreferenceInput{
			AccessToken:              aws.String(task.AccessToken),
			SoftwareTokenMfaSettings: softwareTokenSettings,
		}

		_, err = cognitoClient.SetUserMFAPreference(task.Context, mfaPreferenceInput)

		if err != nil {
			task.ResultChan <- TaskResult{
				Err: loginTypes.NewInternalError("failed to enable software token MFA", err),
			}
			return
		}
	}

	task.ResultChan <- TaskResult{}
}

func processVerifyUpdateMFATask(task verifyMFAUpdateTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(processingLogLevel, "processing")

	session := getLoginSession(task.Task)
	if session == nil {
		return
	}

	switch session.NextStep {
	case NextStepMFASoftwareTokenSetupVerify:
		verifyMFASetupSoftwareToken(task)
	default:
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewBadRequestError("MFA method not supported", "MFA method not supported", nil),
		}
		return
	}
}

func processSelectMFATask(task selectMFATask) {
	if !checkTaskContext(task.Task) {
		return
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(processingLogLevel, "processing")

	unlockSession := lockLoginSession(task.SessionKey)
	defer unlockSession()

	requestLogger.Log(processingLogLevel, "processing", zap.String("sessionKey", task.SessionKey), zap.String("mfaType", string(task.MFAType)))

	session := getLoginSession(task.Task)
	if session == nil || !checkNextStep(task.Task, session, NextStepMFASelect) {
		return
	}

	t, ok := reverseMFAMapping[task.MFAType]
	if !ok {
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError("Unsupported MFA type", "Unsupported MFA type", nil),
		}
		return
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
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError(err.Error(), "Authentication error", err),
		}
		return
	}

	handleChallenge(result.ChallengeName, result.ChallengeParameters, task.Task, *result.Session)
}

func findUsersByEmail(ctx context.Context, email string) ([]cognitoTypes.UserType, loginTypes.GenericError) {
	filter := fmt.Sprintf("email = \"%s\"", email)

	input := &cognitoidentityprovider.ListUsersInput{
		UserPoolId: aws.String(cognitoUserPoolID),
		Filter:     aws.String(filter),
		Limit:      aws.Int32(2),
	}

	result, err := cognitoClient.ListUsers(ctx, input)
	if err != nil {
		return nil, loginTypes.NewInternalError(err.Error(), err)
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

func processInitiatePasswordResetTask(task initiatePasswordResetTask) {
	if !checkTaskContext(task.Task) {
		return
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

			resetSettings := passwordreset.GetSettings()

			if err := sessionStorage.CreateResetPasswordSession(context.Background(), token, *user.Username, task.Email, time.Now().Add(resetSettings.ValidFor)); err != nil {
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
					ToAddresses: []string{task.Email},
				},
				Template:     aws.String(resetSettings.TemplateName),
				TemplateData: aws.String(string(templateJSON)),
			}

			result, err := sesClient.SendTemplatedEmail(context.Background(), input)
			if err != nil {
				requestLogger.Error("failed to send an email", zap.Error(err))
				return
			}

			requestLogger.Info("sent reset password message", zap.String("email", task.Email), zap.String("user", *user.Username), zap.String("messageId", *result.MessageId))
		}
	}()

	task.ResultChan <- TaskResult{}
}

func redirectToPasswordErrorPageIfConfigured(task Task, errorRedirectURL string) bool {
	if errorRedirectURL != "" {
		task.ResultChan <- TaskResult{
			Payload: errorRedirectURL,
		}
		return true
	}
	return false
}

func processResetPasswordTask(task resetPasswordTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(processingLogLevel, "processing")

	resetSettings := passwordreset.GetSettings()

	session, err := sessionStorage.GetResetPasswordSession(task.Context, task.Token)
	if err != nil {
		if !redirectToPasswordErrorPageIfConfigured(task.Task, resetSettings.ErrorRedirectURL) {
			task.ResultChan <- TaskResult{
				Err: loginTypes.NewInternalError("failed to retrieve password reset session", err),
			}
		}
		return
	}
	if session == nil {
		if !redirectToPasswordErrorPageIfConfigured(task.Task, resetSettings.ErrorRedirectURL) {
			task.ResultChan <- TaskResult{
				Err: &loginTypes.ResetPasswordSessionExpiredOrDoesNotExistError,
			}
		}
		return
	}

	err = sessionStorage.DropResetPasswordSession(task.Context, task.Token)
	if err != nil {
		if !redirectToPasswordErrorPageIfConfigured(task.Task, resetSettings.ErrorRedirectURL) {
			task.ResultChan <- TaskResult{
				Err: loginTypes.NewInternalError("failed to drop password reset session", err),
			}
		}
		return
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
		if !redirectToPasswordErrorPageIfConfigured(task.Task, resetSettings.ErrorRedirectURL) {
			task.ResultChan <- TaskResult{
				Err: loginTypes.NewInternalError(err.Error(), err),
			}
		}
		return
	}

	requestLogger.Info("user password has been reset",
		zap.String("user", session.User),
		zap.String("deliveryMethod", string(result.CodeDeliveryDetails.DeliveryMedium)),
		zap.String("destination", *result.CodeDeliveryDetails.Destination),
	)

	task.ResultChan <- TaskResult{
		Payload: fmt.Sprintf(resetSettings.RedirectURL, session.User),
	}
}

func processFinalizePasswordResetTask(task finalizePasswordResetTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	requestLogger := getRequestLoggerFromTask(task.Task)

	requestLogger.Log(processingLogLevel, "processing", zap.String("user", task.User))

	input := &cognitoidentityprovider.ConfirmForgotPasswordInput{
		ClientId:         aws.String(cognitoClientID),
		Username:         aws.String(task.User),
		ConfirmationCode: aws.String(task.Code),
		Password:         aws.String(task.Password),
	}

	if cognitoClientSecret != "" {
		input.SecretHash = aws.String(computeSecretHash(cognitoClientSecret, task.User, cognitoClientID))
	}

	_, err := cognitoClient.ConfirmForgotPassword(task.Context, input)

	if err != nil {
		var cme *cognitoTypes.CodeMismatchException
		if errors.As(err, &cme) {
			task.ResultChan <- TaskResult{
				Err: loginTypes.InvalidVerificationCodeError,
			}
			return
		}

		task.ResultChan <- TaskResult{
			Err: loginTypes.NewInternalError(err.Error(), err),
		}
		return
	}

	requestLogger.Info("user finalized password reset",
		zap.String("user", task.User),
	)

	task.ResultChan <- TaskResult{}
}
