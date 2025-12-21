package cognito

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
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
	"go.uber.org/zap"
)

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
			Err: loginTypes.NewGenericAuthenticationError("Challenge is empty", "Authentication error", nil),
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
				Err: loginTypes.NewGenericAuthenticationError("No MFA methods available", "Authentication error", nil),
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
				Err: loginTypes.NewGenericAuthenticationError("No MFA methods available", "Authentication error", nil),
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
			Err: loginTypes.NewGenericAuthenticationError("Unsupported challenge type", "Authentication error", nil),
		}
		return
	}

	createLoginSession(task.SessionKey, cognitoSessions, nextStep, time.Now().Add(loginSessionValidFor), sessionTag)
	tr.NextStep = nextStep
	task.ResultChan <- tr
}

func getTaskSession(t Task) (LoginSession, bool) {
	session, ok := getLoginSession(t.SessionKey)
	if !ok {
		t.ResultChan <- TaskResult{
			Err: loginTypes.NewLoginSessionExpiredOrDoesNotExistError(),
		}
		return session, false
	}
	return session, true
}

func checkNextStep(t Task, s LoginSession, expectedStep NextStep) bool {
	if s.nextStep != expectedStep {
		t.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError(fmt.Sprintf("unexpected next step: %s; expected: %s", s.nextStep, expectedStep), "authentication error", nil),
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
			Err: loginTypes.NewGenericAuthenticationError(err.Error(), "Authentication error", err),
		}
		return false
	}
	return true
}

func processLoginTask(task loginTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	unlockSession := lockLoginSession(task.SessionKey)
	defer unlockSession()

	logger.Debug("processLoginTask", zap.String("sessionKey", task.SessionKey), zap.String("username", task.User))

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
			Err: loginTypes.NewGenericAuthenticationError(err.Error(), "Authentication error", err),
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
				Err: loginTypes.NewGenericAuthenticationError("no challenge requested and no authentication result received", "authentication error", nil),
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

	unlockSession := lockLoginSession(task.SessionKey)
	defer unlockSession()

	logger.Debug("processMFASetupTask", zap.String("sessionKey", task.SessionKey), zap.String("username", task.User))

	var session LoginSession
	if s, ok := getTaskSession(task.Task); !ok || !checkNextStep(task.Task, s, NextStepMFASetup) {
		return
	} else {
		session = s
	}

	switch task.MFAType {
	case loginTypes.MFATypeSoftwareToken:
		logger.Debug("processMFASetupTask MFATypeSoftwareToken", zap.String("username", task.User))

		associateInput := &cognitoidentityprovider.AssociateSoftwareTokenInput{
			Session: &session.cognitoSession,
		}

		associateResult, err := cognitoClient.AssociateSoftwareToken(task.Context, associateInput)
		if err != nil {
			task.ResultChan <- TaskResult{
				Err: loginTypes.NewGenericAuthenticationError(err.Error(), "Authentication error", err),
			}
			return
		}

		createLoginSession(task.SessionKey, *associateResult.Session, NextStepMFASoftwareTokenSetupVerify, time.Now().Add(loginSessionValidFor), nil)
		task.ResultChan <- TaskResult{
			NextStep:   NextStepMFASoftwareTokenSetupVerify,
			SessionKey: task.SessionKey,
			Payload:    associateResult.SecretCode,
		}
		return
	}

	task.ResultChan <- TaskResult{
		Err: loginTypes.NewGenericAuthenticationError("Unsupported MFA setup type", "Authentication error", nil),
	}
}

func processMFASetupVerifySoftwareTokenTask(task mfaSetupVerifySoftwareTokenTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	unlockSession := lockLoginSession(task.SessionKey)
	defer unlockSession()

	logger.Debug("processMFASetupVerifySoftwareTokenTask", zap.String("sessionKey", task.SessionKey), zap.String("username", task.User))

	var session LoginSession
	if s, ok := getTaskSession(task.Task); !ok || !checkNextStep(task.Task, s, NextStepMFASoftwareTokenSetupVerify) {
		return
	} else {
		session = s
	}

	verifyInput := &cognitoidentityprovider.VerifySoftwareTokenInput{
		Session:  &session.cognitoSession,
		UserCode: aws.String(task.Code),
		//FriendlyDeviceName: aws.String("MyDevice"), // Optional device name
	}

	verifyResult, err := cognitoClient.VerifySoftwareToken(task.Context, verifyInput)
	if err != nil {
		var est *cognitoTypes.EnableSoftwareTokenMFAException
		if errors.As(err, &est) {
			task.ResultChan <- TaskResult{
				Err: loginTypes.InvalidMFASetupSoftwareTokenError,
			}
			return
		}
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError(err.Error(), "Authentication error", err),
		}
		return
	}

	if verifyResult.Status != cognitoTypes.VerifySoftwareTokenResponseTypeSuccess {
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError("no error raised but response is not successful", "Authentication error", nil),
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
			Err: loginTypes.NewGenericAuthenticationError(err.Error(), "Authentication error", err),
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

func verifyMFACode(session LoginSession, task mfaVerifyTask, step NextStep) {
	challengeResp := &cognitoidentityprovider.RespondToAuthChallengeInput{
		ClientId: aws.String(cognitoClientID),
		Session:  &session.cognitoSession,
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
			Err: loginTypes.NewGenericAuthenticationError(err.Error(), "Authentication error", err),
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
				Err: loginTypes.NewGenericAuthenticationError("no challenge requested and no authentication result received", "authentication error", nil),
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

	unlockSession := lockLoginSession(task.SessionKey)
	defer unlockSession()

	if !checkTaskContext(task.Task) {
		return
	}

	var session LoginSession
	if s, ok := getTaskSession(task.Task); !ok {
		return
	} else {
		session = s
	}

	switch session.nextStep {
	case NextStepMFASoftwareTokenVerify:
		fallthrough
	case NextStepMFAEMailVerify:
		fallthrough
	case NextStepMFASMSVerify:
		verifyMFACode(session, task, session.nextStep)
	}
	task.ResultChan <- TaskResult{
		Err: loginTypes.NewGenericAuthenticationError(fmt.Sprintf("unexpected next step: %s", session.nextStep), "authentication error", nil),
	}
}

func processRefreshTokenTask(task refreshTokenTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	var err error
	var authResult *cognitoTypes.AuthenticationResultType

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
			Err: loginTypes.NewGenericAuthenticationError(err.Error(), "Authentication error", err),
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
		Err: loginTypes.NewGenericAuthenticationError("no authentication result received", "authentication error", nil),
	}
}

func processSatisfyPasswordUpdateRequestTask(task satisfyPasswordUpdateRequestTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	unlockSession := lockLoginSession(task.SessionKey)
	defer unlockSession()

	logger.Debug("processSatisfyPasswordUpdateRequestTask", zap.String("sessionKey", task.SessionKey), zap.String("username", task.User))

	var session LoginSession
	if s, ok := getTaskSession(task.Task); !ok || !checkNextStep(task.Task, s, NextStepNewPassword) {
		return
	} else {
		session = s
	}

	input := &cognitoidentityprovider.RespondToAuthChallengeInput{
		ChallengeName: cognitoTypes.ChallengeNameTypeNewPasswordRequired,
		ClientId:      aws.String(cognitoClientID),
		Session:       aws.String(session.cognitoSession),
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
			Err: loginTypes.NewGenericAuthenticationError(err.Error(), "Authentication error", err),
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
				Err: loginTypes.NewGenericAuthenticationError("no challenge requested and no authentication result received", "authentication error", nil),
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

	input := &cognitoidentityprovider.RevokeTokenInput{
		ClientId: aws.String(cognitoClientID),
		Token:    aws.String(task.RefreshToken),
	}

	if cognitoClientSecret != "" {
		input.ClientSecret = aws.String(cognitoClientSecret)
	}

	_, err := cognitoClient.RevokeToken(task.Context, input)

	if err != nil {
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError(err.Error(), "Logout error", err),
		}
		return
	}

	task.ResultChan <- TaskResult{}
}

func processUpdatePasswordTask(task updatePasswordTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	input := &cognitoidentityprovider.ChangePasswordInput{
		AccessToken:      aws.String(task.AccessToken),
		PreviousPassword: aws.String(task.CurrentPassword),
		ProposedPassword: aws.String(task.NewPassword),
	}

	_, err := cognitoClient.ChangePassword(task.Context, input)

	if err != nil {
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError(err.Error(), "Logout error", err),
		}
		return
	}

	task.ResultChan <- TaskResult{}
}

func processGetMFAStatusTask(task getMFAStatusTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	token, err := jwksValidator.ValidateToken(task.AccessToken)

	var username string

	if err != nil {
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError(err.Error(), "Invalid token", err),
		}
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); token.Valid && ok {
		if un, ok := claims["username"].(string); ok {
			username = un
		}
	} else {
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError("token is invalid or does not contain username", "Invalid token", nil),
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
			Err: loginTypes.NewGenericAuthenticationError(err.Error(), "Logout error", err),
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

func updateSoftwareToken(task updateMFATask) {
	//softwareTokenSettings := &cognitoTypes.SoftwareTokenMfaSettingsType{
	//	Enabled:      false,
	//	PreferredMfa: false,
	//}

	//input := &cognitoidentityprovider.SetUserMFAPreferenceInput{
	//	AccessToken:              aws.String(task.AccessToken),
	//	SoftwareTokenMfaSettings: softwareTokenSettings,
	//}
	//
	//_, err := cognitoClient.SetUserMFAPreference(task.Context, input)
	//
	//if err != nil {
	//	task.ResultChan <- TaskResult{
	//		Err: loginTypes.NewInternalError(err.Error(), "Internal error", err),
	//	}
	//	return
	//}

	associateInput := &cognitoidentityprovider.AssociateSoftwareTokenInput{
		AccessToken: aws.String(task.AccessToken),
	}

	associateResult, err := cognitoClient.AssociateSoftwareToken(context.TODO(), associateInput)
	if err != nil {
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewInternalError(err.Error(), "Internal error", err),
		}
		return
	}

	createLoginSession(task.SessionKey, "", NextStepMFASoftwareTokenSetupVerify, time.Now().Add(loginSessionValidFor), nil)
	task.ResultChan <- TaskResult{
		NextStep:   NextStepMFASoftwareTokenSetupVerify,
		SessionKey: task.SessionKey,
		Payload:    associateResult.SecretCode,
	}
}

func processUpdateMFATask(task updateMFATask) {
	if !checkTaskContext(task.Task) {
		return
	}

	switch task.MFAType {
	case loginTypes.MFATypeSoftwareToken:
		updateSoftwareToken(task)
		return
	default:
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError("MFA method not supported", "MFA method not supported", nil),
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
				Err: loginTypes.InvalidMFASetupSoftwareTokenError,
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
			Err: loginTypes.NewGenericAuthenticationError("no error raised but response is not successful", "Authentication error", nil),
		}
		return
	}

	task.ResultChan <- TaskResult{}
}

func processVerifyUpdateMFATask(task verifyMFAUpdateTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	var session LoginSession
	if s, ok := getTaskSession(task.Task); !ok {
		return
	} else {
		session = s
	}

	switch session.nextStep {
	case NextStepMFASoftwareTokenSetupVerify:
		verifyMFASetupSoftwareToken(task)
	default:
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError("MFA method not supported", "Invalid input", nil),
		}
		return
	}
}

func processSelectMFATask(task selectMFATask) {
	if !checkTaskContext(task.Task) {
		return
	}

	unlockSession := lockLoginSession(task.SessionKey)
	defer unlockSession()

	logger.Debug("processChooseMFATask", zap.String("sessionKey", task.SessionKey), zap.String("mfaType", string(task.MFAType)))

	var session LoginSession
	if s, ok := getTaskSession(task.Task); !ok || !checkNextStep(task.Task, s, NextStepMFASelect) {
		return
	} else {
		session = s
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
		Session:       aws.String(session.cognitoSession),
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
		return nil, loginTypes.NewInternalError(err.Error(), "internal error", err)
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

	users, err := findUsersByEmail(task.Context, task.Email)
	if err != nil {
		task.ResultChan <- TaskResult{
			Err: err,
		}
		return
	}

	simulateAPICallDelay := false
	if len(users) > 1 {
		logger.Error("found multiple users with the same email", zap.String("email", task.Email))
		simulateAPICallDelay = true
	} else if len(users) == 0 {
		logger.Warn("attempted password recovery for non existing email", zap.String("email", task.Email))
		simulateAPICallDelay = true
	}

	if simulateAPICallDelay {
		time.Sleep(time.Duration(rand.Intn(200)+150) * time.Millisecond)
	} else {
		token := tools.GenerateRandomString(32)
		user := users[0]

		resetSettings := passwordreset.GetSettings()

		createResetPasswordSession(token, *user.Username, task.Email, time.Now().Add(resetSettings.ValidFor))

		resetLink := fmt.Sprintf("%s/v1/password/reset?token=%s", config.GetURLBase(), token)

		templateData := map[string]interface{}{
			"username":      *user.Username,
			"resetLink":     resetLink,
			"expiryMinutes": uint64(resetSettings.ValidFor.Minutes()),
			"companyName":   resetSettings.Company,
			"currentYear":   resetSettings.Year,
		}

		templateJSON, err := json.Marshal(templateData)
		if err != nil {
			task.ResultChan <- TaskResult{
				Err: loginTypes.NewInternalError(err.Error(), "internal error", err),
			}
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

		result, err := sesClient.SendTemplatedEmail(task.Context, input)
		if err != nil {
			task.ResultChan <- TaskResult{
				Err: loginTypes.NewInternalError(err.Error(), "internal error", err),
			}
			return
		}

		logger.Info("sent reset password message", zap.String("email", task.Email), zap.String("user", *user.Username), zap.String("messageId", *result.MessageId))

	}

	task.ResultChan <- TaskResult{}
}

func processResetPasswordTask(task resetPasswordTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	session, ok := getResetPasswordSession(task.Token)
	if !ok || session.used {
		task.ResultChan <- TaskResult{
			Err: &loginTypes.ResetPasswordSessionExpiredOrDoesNotExistError,
		}
		return
	}

	session.used = true

	input := &cognitoidentityprovider.ForgotPasswordInput{
		ClientId: aws.String(cognitoClientID),
		Username: aws.String(session.user),
	}

	if cognitoClientSecret != "" {
		input.SecretHash = aws.String(computeSecretHash(cognitoClientSecret, session.user, cognitoClientID))
	}

	result, err := cognitoClient.ForgotPassword(task.Context, input)

	if err != nil {
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewInternalError(err.Error(), "internal error", err),
		}
		return
	}

	logger.Info("user password has been reset",
		zap.String("user", session.user),
		zap.String("deliveryMethod", string(result.CodeDeliveryDetails.DeliveryMedium)),
		zap.String("destination", *result.CodeDeliveryDetails.Destination),
	)

	resetSettings := passwordreset.GetSettings()

	task.ResultChan <- TaskResult{
		Payload: fmt.Sprintf(resetSettings.RedirectURL, session.user),
	}
}

func processFinalizePasswordResetTask(task finalizePasswordResetTask) {
	if !checkTaskContext(task.Task) {
		return
	}

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
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewInternalError(err.Error(), "internal error", err),
		}
		return
	}

	logger.Info("user finalized password reset",
		zap.String("user", task.User),
	)

	task.ResultChan <- TaskResult{}
}
