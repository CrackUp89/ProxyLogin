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
	"go.uber.org/zap"
)

var (
	cognitoClientID     = ""
	cognitoClientSecret = ""
	cognitoUserPoolID   = ""
	useAuthToRefresh    bool
	awsConfig           aws.Config
	client              *cognitoidentityprovider.Client
)

var sessionMutexManager = tools.NamedMutexManager{}

func SetClientDetails(clientID string, clientSecret string) error {
	if clientID == "" {
		return errors.New("clientID is empty")
	}

	cognitoClientID = clientID
	cognitoClientSecret = clientSecret

	return nil
}

func SetUserPoolID(userPoolID string) {
	cognitoUserPoolID = userPoolID
}

func describeUserPool(client *cognitoidentityprovider.Client, userPoolId, clientId string) *cognitoidentityprovider.DescribeUserPoolClientOutput {
	input := &cognitoidentityprovider.DescribeUserPoolClientInput{
		UserPoolId: aws.String(userPoolId),
		ClientId:   aws.String(clientId),
	}

	result, err := client.DescribeUserPoolClient(context.Background(), input)
	if err != nil {
		logger.Fatal("Failed to describe user pool", zap.Error(err))
	}
	return result
}

func Initialize() {
	var err error
	awsConfig, err = config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	client = cognitoidentityprovider.NewFromConfig(awsConfig)

	poolDescription := describeUserPool(client, cognitoUserPoolID, cognitoClientID)

	useAuthToRefresh = poolDescription.UserPoolClient.EnableTokenRevocation != nil && *poolDescription.UserPoolClient.EnableTokenRevocation

	if poolDescription.UserPoolClient.AuthSessionValidity != nil {
		sessionValidFor = float64(*poolDescription.UserPoolClient.AuthSessionValidity*60) * 1.0
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

func handleChallenge(challenge types.ChallengeNameType, t Task, cognitoSessions string, payload interface{}) {

	if challenge == "" {
		t.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError("Authentication error", "Challenge is empty", nil),
		}
		return
	}

	switch challenge {
	case types.ChallengeNameTypeMfaSetup:
		SetSession(t.SessionKey, cognitoSessions, NextStepMFASetup, time.Now())
		t.ResultChan <- TaskResult{
			NextStep:   NextStepMFASetup,
			SessionKey: t.SessionKey,
			Payload:    payload,
		}
		break
	case types.ChallengeNameTypeSoftwareTokenMfa:
		SetSession(t.SessionKey, cognitoSessions, NextStepMFASoftwareTokenVerify, time.Now())
		t.ResultChan <- TaskResult{
			NextStep:   NextStepMFASoftwareTokenVerify,
			SessionKey: t.SessionKey,
			Payload:    payload,
		}
		break
	default:
		t.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError("Authentication error", "Unsupported challenge type", nil),
		}
	}
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

var mfasMapping = map[string]loginTypes.MFASetupType{
	"SOFTWARE_TOKEN_MFA": loginTypes.MFASetupTypeSoftwareToken,
}

func mapMFAS(mfasTypes []string) []loginTypes.MFASetupType {
	r := make([]loginTypes.MFASetupType, 0, len(mfasTypes))
	for _, mfasType := range mfasTypes {
		if m, ok := mfasMapping[strings.Trim(mfasType, "\"")]; ok {
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

	payload := make(map[string]interface{})

	if result.ChallengeName == types.ChallengeNameTypeMfaSetup {
		v, ok := result.ChallengeParameters["MFAS_CAN_SETUP"]
		if ok {
			payload["available_mfa_methods"] = mapMFAS(strings.Split(strings.Trim(v, "[]"), ","))
		} else {
			task.ResultChan <- TaskResult{
				Err: loginTypes.NewGenericAuthenticationError("No MFA methods available", "Authentication error", nil),
			}
			return
		}
	}

	handleChallenge(result.ChallengeName, task.Task, *result.Session, payload)
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
	case loginTypes.MFASetupTypeSoftwareToken:
		logger.Debug("processMFASetupTask MFASetupTypeSoftwareToken", zap.String("username", task.Username))

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

		SetSession(task.SessionKey, *associateResult.Session, NextStepMFASoftwareTokenSetupVerify, time.Now())
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
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError(err.Error(), "Authentication error", err),
		}
		return
	}

	if verifyResult.Status != types.VerifySoftwareTokenResponseTypeSuccess {
		task.ResultChan <- TaskResult{
			Err: loginTypes.InvalidMFASetupSoftwareTokenError,
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

	handleChallenge(finalResult.ChallengeName, task.Task, *finalResult.Session, nil)
}

func processMFASoftwareTokenVerifyTask(task MFASoftwareTokenVerifyTask) {
	if !checkTaskContext(task.Task) {
		return
	}

	unlockSession := lockSession(task.SessionKey)
	defer unlockSession()

	var session LoginSession
	if s, ok := getTaskSession(task.Task); !ok || !checkNextStep(task.Task, s, NextStepMFASoftwareTokenVerify) {
		return
	} else {
		session = s
	}

	challengeResp := &cognitoidentityprovider.RespondToAuthChallengeInput{
		ChallengeName: types.ChallengeNameTypeSoftwareTokenMfa,
		ClientId:      aws.String(cognitoClientID),
		Session:       &session.cognitoSession,
		ChallengeResponses: map[string]string{
			"USERNAME":                task.Username,
			"SOFTWARE_TOKEN_MFA_CODE": task.Code,
		},
	}

	if cognitoClientSecret != "" {
		challengeResp.ChallengeResponses["SECRET_HASH"] = computeSecretHash(cognitoClientSecret, task.Username, cognitoClientID)
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

	handleChallenge(result.ChallengeName, task.Task, *result.Session, nil)
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
	} else {
		task.ResultChan <- TaskResult{
			Err: loginTypes.NewGenericAuthenticationError("no authentication result received", "authentication error", nil),
		}
	}
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
