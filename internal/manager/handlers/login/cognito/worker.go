package cognito

import (
	"context"
	"proxylogin/internal/manager/handlers/login/types"
	"proxylogin/internal/manager/tools"

	"go.uber.org/zap"
)

var workersLogger = tools.NewLogger("Cognito.Workers")

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
	MFAType  types.MFASetupType
	Task
}

var maxMFASetupTasks = 1000
var mfaSetupTasks = make(chan MFASetupTask)

func AddMFASetupTask(ctx context.Context, sessionKey string, username string, setupType types.MFASetupType) (TaskResultChan, error) {
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

type MFASoftwareTokenVerifyTask struct {
	Username string
	Code     string
	Task
}

var maxMFASoftwareTokenVerifyTasks = 1000
var mfaSoftwareTokenVerifyTasks = make(chan MFASoftwareTokenVerifyTask)

func AddMFASoftwareTokenVerifyTask(ctx context.Context, sessionKey string, username string, code string) (TaskResultChan, error) {
	if len(mfaSoftwareTokenVerifyTasks) >= maxMFASoftwareTokenVerifyTasks {
		return nil, types.NewTooManyTasks("MFASoftwareTokenVerifyTask")
	}
	resultChan := make(TaskResultChan)
	mfaSoftwareTokenVerifyTasks <- MFASoftwareTokenVerifyTask{username, code, Task{ctx, sessionKey, resultChan}}
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
		return nil, types.NewTooManyTasks("LogOutTask")
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

var maxUpdatePasswordTask = 1000
var updatePasswordTasks = make(chan updatePasswordTask)

func AddUpdatePasswordTask(ctx context.Context, accessToken string, currentPassword string, newPassword string) (TaskResultChan, error) {
	if len(updatePasswordTasks) >= maxUpdatePasswordTask {
		return nil, types.NewTooManyTasks("LogOutTask")
	}
	resultChan := make(TaskResultChan)
	updatePasswordTasks <- updatePasswordTask{accessToken, currentPassword, newPassword, Task{ctx, "", resultChan}}
	return resultChan, nil
}

func startWorker() chan bool {
	stopChannel := make(chan bool)
	go func() {
		for {
			select {
			case t := <-loginTasks:
				processLoginTask(t)
				break
			case t := <-mfaSetupTasks:
				processMFASetupTask(t)
				break
			case t := <-mfaSetupSoftwareTokenVerifyTasks:
				processMFASetupVerifySoftwareTokenTask(t)
				break
			case t := <-mfaSoftwareTokenVerifyTasks:
				processMFASoftwareTokenVerifyTask(t)
				break
			case t := <-refreshTokenTasks:
				processRefreshTokenTask(t)
				break
			case t := <-logOutTasks:
				processLogOutTask(t)
				break
			case t := <-satisfyPasswordUpdateRequestTasks:
				processSatisfyPasswordUpdateRequestTask(t)
				break
			case t := <-updatePasswordTasks:
				processUpdatePasswordTask(t)
				break
			case <-stopChannel:
				return
			}
		}
	}()
	return stopChannel
}

func StartWorkers(num uint64) func() {
	stopChannels := make([]chan bool, num)
	for i := uint64(0); i < num; i++ {
		stopChannels[i] = startWorker()
	}
	workersLogger.Info("Workers started", zap.Uint64("num", num))
	return func() {
		for _, stopChannel := range stopChannels {
			stopChannel <- true
		}
	}
}
