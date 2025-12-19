package cognito

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	loginTypes "proxylogin/internal/manager/handlers/login/types"
	"proxylogin/internal/manager/tools"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

var (
	cognitoClientID          = ""
	cognitoClientSecret      = ""
	cognitoUserPoolID        = ""
	cognitoJWKSIssuer        = ""
	cognitoJWKSKeySigningURL = ""
	jwksValidator            *tools.JWKSValidator
	useAuthToRefresh         bool
	awsConfig                aws.Config
	client                   *cognitoidentityprovider.Client
	poolClientDescription    *types.UserPoolClientType
	poolDescription          *types.UserPoolType
)

var sessionMutexManager = tools.NamedMutexManager{}

func SetClientDetails(clientID, clientSecret string) error {
	if clientID == "" {
		return errors.New("clientID is empty")
	}

	cognitoClientID = clientID
	cognitoClientSecret = clientSecret

	return nil
}

func SetJWKSDetails(jwksIssuer, jwksKeySigningURL string) error {
	if jwksIssuer == "" {
		return errors.New("jwksIssuer is empty")
	}
	if jwksKeySigningURL == "" {
		return errors.New("jwksKeySigningURL is empty")
	}

	cognitoJWKSIssuer = jwksIssuer
	cognitoJWKSKeySigningURL = jwksKeySigningURL

	var err error
	jwksValidator, err = tools.NewJWKSValidator(cognitoJWKSKeySigningURL, cognitoJWKSIssuer, "")

	return err
}

func SetUserPoolID(userPoolID string) {
	cognitoUserPoolID = userPoolID
}

func describeUserPoolClient(client *cognitoidentityprovider.Client, userPoolId, clientId string) *types.UserPoolClientType {
	input := &cognitoidentityprovider.DescribeUserPoolClientInput{
		UserPoolId: aws.String(userPoolId),
		ClientId:   aws.String(clientId),
	}

	result, err := client.DescribeUserPoolClient(context.Background(), input)

	if err != nil {
		logger.Fatal("Failed to describe user pool", zap.Error(err))
	}
	return result.UserPoolClient
}

func describeUserPool(client *cognitoidentityprovider.Client, userPoolId string) *types.UserPoolType {
	input := &cognitoidentityprovider.DescribeUserPoolInput{
		UserPoolId: aws.String(userPoolId),
	}

	result, err := client.DescribeUserPool(context.Background(), input)

	if err != nil {
		logger.Fatal("Failed to describe user pool", zap.Error(err))
	}

	return result.UserPool
}

func Initialize() {
	var err error
	awsConfig, err = config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	client = cognitoidentityprovider.NewFromConfig(awsConfig)

	poolClientDescription = describeUserPoolClient(client, cognitoUserPoolID, cognitoClientID)
	poolDescription = describeUserPool(client, cognitoUserPoolID)

	useAuthToRefresh = poolClientDescription.EnableTokenRevocation != nil && *poolClientDescription.EnableTokenRevocation

	if poolClientDescription.AuthSessionValidity != nil {
		sessionValidFor = float64(*poolClientDescription.AuthSessionValidity*60) * 1.0
	}
}

func computeSecretHash(clientSecret, username, clientId string) string {
	message := username + clientId
	key := []byte(clientSecret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func lockSession(sessionKey string) func() {
	lock := sessionMutexManager.GetNamedMutex(sessionKey)
	lock.Lock()
	return func() { lock.Unlock() }
}

func authResultToTokenSet(authResult *types.AuthenticationResultType) loginTypes.TokenSet {
	result := loginTypes.TokenSet{
		AccessToken: *authResult.AccessToken,
		IdToken:     *authResult.IdToken,
	}
	if authResult.RefreshToken != nil {
		result.RefreshToken = *authResult.RefreshToken
	}
	return result
}

func handleChallenge(challenge types.ChallengeNameType, challengeParameters map[string]string, task Task, cognitoSessions string) {

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
	case types.ChallengeNameTypeSelectMfaType:
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
	case types.ChallengeNameTypeMfaSetup:
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
	case types.ChallengeNameTypeSoftwareTokenMfa:
		nextStep = NextStepMFASoftwareTokenVerify
		break
	case types.ChallengeNameTypeEmailOtp:
		nextStep = NextStepMFAEMailVerify
		break
	case types.ChallengeNameTypeSmsMfa:
		nextStep = NextStepMFAEMailVerify
		break
	case types.ChallengeNameTypeNewPasswordRequired:
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

	SetSession(task.SessionKey, cognitoSessions, nextStep, time.Now(), sessionTag)
	tr.NextStep = nextStep
	task.ResultChan <- tr
}

func getTaskSession(t Task) (LoginSession, bool) {
	session, ok := GetSession(t.SessionKey)
	if !ok {
		t.ResultChan <- TaskResult{
			Err: loginTypes.NewSessionExpiredOrDoesNotExistError(),
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

func processLoginTask(task LoginTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	unlockSession := lockSession(task.SessionKey)
	defer unlockSession()

	logger.Debug("processLoginTask", zap.String("sessionKey", task.SessionKey), zap.String("username", task.Username))

	authInput := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: types.AuthFlowTypeUserPasswordAuth,
		ClientId: aws.String(cognitoClientID),
		AuthParameters: map[string]string{
			"USERNAME": task.Username,
			"PASSWORD": task.Password,
		},
	}

	if cognitoClientSecret != "" {
		authInput.AuthParameters["SECRET_HASH"] = computeSecretHash(cognitoClientSecret, task.Username, cognitoClientID)
	}

	result, err := client.InitiateAuth(task.Context, authInput)

	if err != nil {
		var unf *types.UserNotFoundException
		var ip *types.NotAuthorizedException
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

func processMFASetupTask(task MFASetupTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	unlockSession := lockSession(task.SessionKey)
	defer unlockSession()

	logger.Debug("processMFASetupTask", zap.String("sessionKey", task.SessionKey), zap.String("username", task.Username))

	var session LoginSession
	if s, ok := getTaskSession(task.Task); !ok || !checkNextStep(task.Task, s, NextStepMFASetup) {
		return
	} else {
		session = s
	}

	switch task.MFAType {
	case loginTypes.MFATypeSoftwareToken:
		logger.Debug("processMFASetupTask MFATypeSoftwareToken", zap.String("username", task.Username))

		associateInput := &cognitoidentityprovider.AssociateSoftwareTokenInput{
			Session: &session.cognitoSession,
		}

		associateResult, err := client.AssociateSoftwareToken(task.Context, associateInput)
		if err != nil {
			task.ResultChan <- TaskResult{
				Err: loginTypes.NewGenericAuthenticationError(err.Error(), "Authentication error", err),
			}
			return
		}

		SetSession(task.SessionKey, *associateResult.Session, NextStepMFASoftwareTokenSetupVerify, time.Now(), nil)
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

func processMFASetupVerifySoftwareTokenTask(task MFASetupVerifySoftwareTokenTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	unlockSession := lockSession(task.SessionKey)
	defer unlockSession()

	logger.Debug("processMFASetupVerifySoftwareTokenTask", zap.String("sessionKey", task.SessionKey), zap.String("username", task.Username))

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

	verifyResult, err := client.VerifySoftwareToken(task.Context, verifyInput)
	if err != nil {
		var est *types.EnableSoftwareTokenMFAException
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

	if verifyResult.Status != types.VerifySoftwareTokenResponseTypeSuccess {
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError("no error raised but response is not successful", "Authentication error", nil),
		}
		return
	}

	challengeInput := &cognitoidentityprovider.RespondToAuthChallengeInput{
		ChallengeName: types.ChallengeNameTypeMfaSetup,
		ClientId:      aws.String(cognitoClientID),
		Session:       verifyResult.Session,
		ChallengeResponses: map[string]string{
			"USERNAME": task.Username,
		},
	}

	if cognitoClientSecret != "" {
		challengeInput.ChallengeResponses["SECRET_HASH"] = computeSecretHash(cognitoClientSecret, task.Username, cognitoClientID)
	}

	finalResult, err := client.RespondToAuthChallenge(task.Context, challengeInput)
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

func verifyMFACode(session LoginSession, task MFAVerifyTask, step NextStep) {
	challengeResp := &cognitoidentityprovider.RespondToAuthChallengeInput{
		ClientId: aws.String(cognitoClientID),
		Session:  &session.cognitoSession,
		ChallengeResponses: map[string]string{
			"USERNAME": task.Username,
		},
	}

	if cognitoClientSecret != "" {
		challengeResp.ChallengeResponses["SECRET_HASH"] = computeSecretHash(cognitoClientSecret, task.Username, cognitoClientID)
	}

	switch step {
	case NextStepMFASoftwareTokenVerify:
		challengeResp.ChallengeName = types.ChallengeNameTypeSoftwareTokenMfa
		challengeResp.ChallengeResponses["SOFTWARE_TOKEN_MFA_CODE"] = task.Code
		break
	case NextStepMFAEMailVerify:
		challengeResp.ChallengeName = types.ChallengeNameTypeEmailOtp
		challengeResp.ChallengeResponses["EMAIL_OTP_CODE"] = task.Code
		break
	case NextStepMFASMSVerify:
		challengeResp.ChallengeName = types.ChallengeNameTypeSmsMfa
		challengeResp.ChallengeResponses["SMS_OTP_CODE"] = task.Code
		break
	}

	result, err := client.RespondToAuthChallenge(task.Context, challengeResp)
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

func processMFAVerifyTask(task MFAVerifyTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	unlockSession := lockSession(task.SessionKey)
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

func processRefreshTokenTask(task RefreshTokenTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	var err error
	var authResult *types.AuthenticationResultType

	if useAuthToRefresh {
		input := &cognitoidentityprovider.InitiateAuthInput{
			AuthFlow: types.AuthFlowTypeRefreshTokenAuth,
			ClientId: aws.String(cognitoClientID),
			AuthParameters: map[string]string{
				"REFRESH_TOKEN": task.RefreshToken,
			},
		}

		if cognitoClientSecret != "" {
			input.AuthParameters["SECRET_HASH"] = computeSecretHash(cognitoClientSecret, task.Username, cognitoClientID)
		}

		var result *cognitoidentityprovider.InitiateAuthOutput
		result, err = client.InitiateAuth(task.Context, input)
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
		result, err = client.GetTokensFromRefreshToken(task.Context, input)

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

func processSatisfyPasswordUpdateRequestTask(task SatisfyPasswordUpdateRequestTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	unlockSession := lockSession(task.SessionKey)
	defer unlockSession()

	logger.Debug("processSatisfyPasswordUpdateRequestTask", zap.String("sessionKey", task.SessionKey), zap.String("username", task.Username))

	var session LoginSession
	if s, ok := getTaskSession(task.Task); !ok || !checkNextStep(task.Task, s, NextStepNewPassword) {
		return
	} else {
		session = s
	}

	input := &cognitoidentityprovider.RespondToAuthChallengeInput{
		ChallengeName: types.ChallengeNameTypeNewPasswordRequired,
		ClientId:      aws.String(cognitoClientID),
		Session:       aws.String(session.cognitoSession),
		ChallengeResponses: map[string]string{
			"USERNAME":     task.Username,
			"NEW_PASSWORD": task.Password,
		},
	}

	if cognitoClientSecret != "" {
		input.ChallengeResponses["SECRET_HASH"] = computeSecretHash(cognitoClientSecret, task.Username, cognitoClientID)
	}

	result, err := client.RespondToAuthChallenge(task.Context, input)
	if err != nil {
		var pv *types.PasswordHistoryPolicyViolationException
		if errors.As(err, &pv) {
			task.ResultChan <- TaskResult{
				Err: loginTypes.PasswordHistoryError,
			}
			return
		}

		var ip *types.InvalidPasswordException
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

func processLogOutTask(task LogOutTask) {
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

	_, err := client.RevokeToken(task.Context, input)

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

	_, err := client.ChangePassword(task.Context, input)

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

	result, err := client.AdminGetUser(context.TODO(), input)

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
		if poolDescription.MfaConfiguration == types.UserPoolMfaTypeOn {
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
	//softwareTokenSettings := &types.SoftwareTokenMfaSettingsType{
	//	Enabled:      false,
	//	PreferredMfa: false,
	//}

	//input := &cognitoidentityprovider.SetUserMFAPreferenceInput{
	//	AccessToken:              aws.String(task.AccessToken),
	//	SoftwareTokenMfaSettings: softwareTokenSettings,
	//}
	//
	//_, err := client.SetUserMFAPreference(task.Context, input)
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

	associateResult, err := client.AssociateSoftwareToken(context.TODO(), associateInput)
	if err != nil {
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewInternalError(err.Error(), "Internal error", err),
		}
		return
	}

	SetSession(task.SessionKey, "", NextStepMFASoftwareTokenSetupVerify, time.Now(), nil)
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

	result, err := client.VerifySoftwareToken(task.Context, input)
	if err != nil {
		var est *types.EnableSoftwareTokenMFAException
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

	if result.Status != types.VerifySoftwareTokenResponseTypeSuccess {
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

	unlockSession := lockSession(task.SessionKey)
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
		ChallengeName: types.ChallengeNameTypeSelectMfaType,
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

	result, err := client.RespondToAuthChallenge(task.Context, input)
	if err != nil {
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError(err.Error(), "Authentication error", err),
		}
		return
	}

	handleChallenge(result.ChallengeName, result.ChallengeParameters, task.Task, *result.Session)
}
