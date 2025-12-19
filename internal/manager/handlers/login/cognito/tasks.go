package cognito

import (
	"context"
	"proxylogin/internal/manager/handlers/login/types"
)

type TaskResult struct {
	NextStep   NextStep
	Payload    interface{}
	SessionKey string
	Err        types.GenericError
}

type TaskResultChan chan TaskResult

type Task struct {
	Context    context.Context
	SessionKey string
	ResultChan TaskResultChan
}

type LoginTask struct {
	Username string
	Password string
	Task
}

var maxLoginTasks = 1000
var loginTasks = make(chan LoginTask)

func AddLoginTask(ctx context.Context, sessionKey string, username string, password string) (TaskResultChan, error) {
	if len(loginTasks) >= maxLoginTasks {
		return nil, types.NewTooManyTasks("LoginTask")
	}
	resultChan := make(TaskResultChan)
	loginTasks <- LoginTask{username, password, Task{ctx, sessionKey, resultChan}}
	return resultChan, nil
}

type MFASetupTask struct {
	Username string
	MFAType  types.MFAType
	Task
}

var maxMFASetupTasks = 1000
var mfaSetupTasks = make(chan MFASetupTask)

func AddMFASetupTask(ctx context.Context, sessionKey string, username string, setupType types.MFAType) (TaskResultChan, error) {
	if len(mfaSetupTasks) >= maxMFASetupTasks {
		return nil, types.NewTooManyTasks("MFASetupTask")
	}
	resultChan := make(TaskResultChan)
	mfaSetupTasks <- MFASetupTask{username, setupType, Task{ctx, sessionKey, resultChan}}
	return resultChan, nil
}

type MFASetupVerifySoftwareTokenTask struct {
	Username string
	Code     string
	Task
}

var maxMFASetupVerifySoftwareTokenTasks = 1000
var mfaSetupSoftwareTokenVerifyTasks = make(chan MFASetupVerifySoftwareTokenTask)

func AddMFASetupVerifySoftwareTokenTask(ctx context.Context, sessionKey string, username string, code string) (TaskResultChan, error) {
	if len(mfaSetupSoftwareTokenVerifyTasks) >= maxMFASetupVerifySoftwareTokenTasks {
		return nil, types.NewTooManyTasks("MFASetupVerifySoftwareTokenTask")
	}
	resultChan := make(TaskResultChan)
	mfaSetupSoftwareTokenVerifyTasks <- MFASetupVerifySoftwareTokenTask{username, code, Task{ctx, sessionKey, resultChan}}
	return resultChan, nil
}

type MFAVerifyTask struct {
	Username string
	Code     string
	Task
}

var maxMFAVerifyTasks = 1000
var mfaVerifyTasks = make(chan MFAVerifyTask)

func AddMFAVerifyTask(ctx context.Context, sessionKey string, username string, code string) (TaskResultChan, error) {
	if len(mfaVerifyTasks) >= maxMFAVerifyTasks {
		return nil, types.NewTooManyTasks("MFAVerifyTask")
	}
	resultChan := make(TaskResultChan)
	mfaVerifyTasks <- MFAVerifyTask{username, code, Task{ctx, sessionKey, resultChan}}
	return resultChan, nil
}

type RefreshTokenTask struct {
	Username     string
	RefreshToken string
	Task
}

var maxRefreshTokenTasks = 1000
var refreshTokenTasks = make(chan RefreshTokenTask)

func AddRefreshTokenTask(ctx context.Context, sessionKey string, user string, refreshToken string) (TaskResultChan, error) {
	if len(refreshTokenTasks) >= maxRefreshTokenTasks {
		return nil, types.NewTooManyTasks("RefreshTokenTask")
	}
	resultChan := make(TaskResultChan)
	refreshTokenTasks <- RefreshTokenTask{user, refreshToken, Task{ctx, sessionKey, resultChan}}
	return resultChan, nil
}

type LogOutTask struct {
	RefreshToken string
	Task
}

var maxLogOutTasks = 1000
var logOutTasks = make(chan LogOutTask)

func AddLogOutTask(ctx context.Context, sessionKey string, refreshToken string) (TaskResultChan, error) {
	if len(refreshTokenTasks) >= maxLogOutTasks {
		return nil, types.NewTooManyTasks("LogOutTask")
	}
	resultChan := make(TaskResultChan)
	logOutTasks <- LogOutTask{refreshToken, Task{ctx, sessionKey, resultChan}}
	return resultChan, nil
}

type SatisfyPasswordUpdateRequestTask struct {
	Username   string
	Password   string
	Attributes map[string]string
	Task
}

var maxSatisfyPasswordUpdateRequestTasks = 1000
var satisfyPasswordUpdateRequestTasks = make(chan SatisfyPasswordUpdateRequestTask)

func AddSatisfyPasswordUpdateRequestTask(ctx context.Context, sessionKey string, user string, password string, attributes map[string]string) (TaskResultChan, error) {
	if len(satisfyPasswordUpdateRequestTasks) >= maxSatisfyPasswordUpdateRequestTasks {
		return nil, types.NewTooManyTasks("SatisfyPasswordUpdateRequestTask")
	}
	resultChan := make(TaskResultChan)
	satisfyPasswordUpdateRequestTasks <- SatisfyPasswordUpdateRequestTask{user, password, attributes, Task{ctx, sessionKey, resultChan}}
	return resultChan, nil
}

type updatePasswordTask struct {
	AccessToken     string
	CurrentPassword string
	NewPassword     string
	Task
}

var maxUpdatePasswordTasks = 1000
var updatePasswordTasks = make(chan updatePasswordTask)

func AddUpdatePasswordTask(ctx context.Context, accessToken string, currentPassword string, newPassword string) (TaskResultChan, error) {
	if len(updatePasswordTasks) >= maxUpdatePasswordTasks {
		return nil, types.NewTooManyTasks("UpdatePasswordTask")
	}
	resultChan := make(TaskResultChan)
	updatePasswordTasks <- updatePasswordTask{accessToken, currentPassword, newPassword, Task{ctx, "", resultChan}}
	return resultChan, nil
}

type getMFAStatusTask struct {
	AccessToken string
	Task
}

var maxGetMFAStatusTask = 1000
var getMFAStatusTasks = make(chan getMFAStatusTask)

func AddGetMFAStatusTask(ctx context.Context, accessToken string) (TaskResultChan, error) {
	if len(getMFAStatusTasks) >= maxGetMFAStatusTask {
		return nil, types.NewTooManyTasks("GetMFAStatusTask")
	}
	resultChan := make(TaskResultChan)
	getMFAStatusTasks <- getMFAStatusTask{accessToken, Task{ctx, "", resultChan}}
	return resultChan, nil
}

type updateMFATask struct {
	AccessToken string
	MFAType     types.MFAType
	Task
}

var maxUpdateMFATasks = 1000
var updateMFATasks = make(chan updateMFATask)

func AddUpdateMFATask(ctx context.Context, sessionKey string, accessToken string, mfaType types.MFAType) (TaskResultChan, error) {
	if len(updateMFATasks) >= maxUpdateMFATasks {
		return nil, types.NewTooManyTasks("UpdateMFATask")
	}
	resultChan := make(TaskResultChan)
	updateMFATasks <- updateMFATask{accessToken, mfaType, Task{ctx, sessionKey, resultChan}}
	return resultChan, nil
}

type verifyMFAUpdateTask struct {
	AccessToken string
	Code        string
	Task
}

var maxVerifyMFAUpdateTasks = 1000
var verifyMFAUpdateTasks = make(chan verifyMFAUpdateTask)

func AddVerifyMFAUpdateTask(ctx context.Context, sessionKey string, accessToken string, code string) (TaskResultChan, error) {
	if len(verifyMFAUpdateTasks) >= maxVerifyMFAUpdateTasks {
		return nil, types.NewTooManyTasks("VerifyUpdateMFATask")
	}
	resultChan := make(TaskResultChan)
	verifyMFAUpdateTasks <- verifyMFAUpdateTask{accessToken, code, Task{ctx, sessionKey, resultChan}}
	return resultChan, nil
}

type selectMFATask struct {
	SessionKey string
	User       string
	MFAType    types.MFAType
	Task
}

var maxSelectMFATasks = 1000
var selectMFATasks = make(chan selectMFATask)

func AddSelectMFATask(ctx context.Context, sessionKey string, user string, MFAType types.MFAType) (TaskResultChan, error) {
	if len(selectMFATasks) >= maxSelectMFATasks {
		return nil, types.NewTooManyTasks("SelectMFATask")
	}
	resultChan := make(TaskResultChan)
	selectMFATasks <- selectMFATask{sessionKey, user, MFAType, Task{ctx, sessionKey, resultChan}}
	return resultChan, nil
}
