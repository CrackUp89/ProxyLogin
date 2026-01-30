package cognito

import (
	"context"
	"fmt"
	"proxylogin/internal/manager/login/types"
	"reflect"
)

type TaskResult struct {
	NextStep   NextStep
	Payload    interface{}
	SessionKey string
	Err        types.GenericError
	Flags      TaskResultFlag
}

type TaskResultChan chan TaskResult

type Task struct {
	Context    context.Context
	ResultChan TaskResultChan
}

func createTaskChan[T any]() (chan T, func() types.GenericError) {
	channel := make(chan T)
	maxLength := 1000
	return channel, func() types.GenericError {
		if len(channel) >= maxLength {
			return types.NewTooManyTasks(fmt.Sprint(reflect.TypeOf(channel)))
		}
		return nil
	}
}

type loginTask struct {
	SessionKey   string
	User         string
	Password     string
	RememberUser bool
	Task
}

var loginTasks, loginTasksValidate = createTaskChan[loginTask]()

func AddLoginTask(ctx context.Context, sessionKey string, user string, password string, rememberUser bool) (TaskResultChan, types.GenericError) {
	if err := loginTasksValidate(); err != nil {
		return nil, err
	}
	resultChan := make(TaskResultChan)
	loginTasks <- loginTask{sessionKey, user, password, rememberUser, Task{ctx, resultChan}}
	return resultChan, nil
}

type mfaSetupTask struct {
	SessionKey string
	User       string
	MFAType    types.MFAType
	Task
}

var mfaSetupTasks, mfaSetupTasksValidate = createTaskChan[mfaSetupTask]()

func AddMFASetupTask(ctx context.Context, sessionKey string, user string, setupType types.MFAType) (TaskResultChan, types.GenericError) {
	if err := mfaSetupTasksValidate(); err != nil {
		return nil, err
	}
	resultChan := make(TaskResultChan)
	mfaSetupTasks <- mfaSetupTask{sessionKey, user, setupType, Task{ctx, resultChan}}
	return resultChan, nil
}

type mfaSetupVerifySoftwareTokenTask struct {
	SessionKey string
	User       string
	Code       string
	Task
}

var mfaSetupSoftwareTokenVerifyTasks, mfaSetupSoftwareTokenVerifyTasksValidate = createTaskChan[mfaSetupVerifySoftwareTokenTask]()

func AddMFASetupVerifySoftwareTokenTask(ctx context.Context, sessionKey string, user string, code string) (TaskResultChan, types.GenericError) {
	if err := mfaSetupSoftwareTokenVerifyTasksValidate(); err != nil {
		return nil, err
	}
	resultChan := make(TaskResultChan)
	mfaSetupSoftwareTokenVerifyTasks <- mfaSetupVerifySoftwareTokenTask{sessionKey, user, code, Task{ctx, resultChan}}
	return resultChan, nil
}

type mfaVerifyTask struct {
	SessionKey string
	User       string
	Code       string
	Task
}

var mfaVerifyTasks, mfaVerifyTasksValidate = createTaskChan[mfaVerifyTask]()

func AddMFAVerifyTask(ctx context.Context, sessionKey string, user string, code string) (TaskResultChan, types.GenericError) {
	if err := mfaVerifyTasksValidate(); err != nil {
		return nil, err
	}
	resultChan := make(TaskResultChan)
	mfaVerifyTasks <- mfaVerifyTask{sessionKey, user, code, Task{ctx, resultChan}}
	return resultChan, nil
}

type refreshTokenTask struct {
	User         string
	RefreshToken string
	Remember     bool
	Task
}

var refreshTokenTasks, refreshTokenTasksValidate = createTaskChan[refreshTokenTask]()

func AddRefreshTokenTask(ctx context.Context, user string, refreshToken string, remember bool) (TaskResultChan, types.GenericError) {
	if err := refreshTokenTasksValidate(); err != nil {
		return nil, err
	}
	resultChan := make(TaskResultChan)
	refreshTokenTasks <- refreshTokenTask{user, refreshToken, remember, Task{ctx, resultChan}}
	return resultChan, nil
}

type logOutTask struct {
	RefreshToken string
	Task
}

var logOutTasks, logOutTasksValidate = createTaskChan[logOutTask]()

func AddLogOutTask(ctx context.Context, refreshToken string) (TaskResultChan, types.GenericError) {
	if err := logOutTasksValidate(); err != nil {
		return nil, err
	}
	resultChan := make(TaskResultChan)
	logOutTasks <- logOutTask{refreshToken, Task{ctx, resultChan}}
	return resultChan, nil
}

type satisfyPasswordUpdateRequestTask struct {
	SessionKey string
	User       string
	Password   string
	Attributes map[string]string
	Task
}

var satisfyPasswordUpdateRequestTasks, satisfyPasswordUpdateRequestTasksValidate = createTaskChan[satisfyPasswordUpdateRequestTask]()

func AddSatisfyPasswordUpdateRequestTask(ctx context.Context, sessionKey string, user string, password string, attributes map[string]string) (TaskResultChan, types.GenericError) {
	if err := satisfyPasswordUpdateRequestTasksValidate(); err != nil {
		return nil, err
	}
	resultChan := make(TaskResultChan)
	satisfyPasswordUpdateRequestTasks <- satisfyPasswordUpdateRequestTask{sessionKey, user, password, attributes, Task{ctx, resultChan}}
	return resultChan, nil
}

type updatePasswordTask struct {
	CurrentPassword string
	NewPassword     string
	Task
}

var updatePasswordTasks, updatePasswordTasksValidate = createTaskChan[updatePasswordTask]()

func AddUpdatePasswordTask(ctx context.Context, currentPassword string, newPassword string) (TaskResultChan, types.GenericError) {
	if err := updatePasswordTasksValidate(); err != nil {
		return nil, err
	}
	resultChan := make(TaskResultChan)
	updatePasswordTasks <- updatePasswordTask{currentPassword, newPassword, Task{ctx, resultChan}}
	return resultChan, nil
}

type getMFAStatusTask struct {
	Task
}

var getMFAStatusTasks, getMFAStatusTasksValidate = createTaskChan[getMFAStatusTask]()

func AddGetMFAStatusTask(ctx context.Context) (TaskResultChan, types.GenericError) {
	if err := getMFAStatusTasksValidate(); err != nil {
		return nil, err
	}
	resultChan := make(TaskResultChan)
	getMFAStatusTasks <- getMFAStatusTask{Task{ctx, resultChan}}
	return resultChan, nil
}

type updateMFASoftwareTokenTask struct {
	SessionKey string
	MFAType    types.MFAType
	Task
}

var updateMFASoftwareTokenTasks, updateMFASoftwareTokenTasksValidate = createTaskChan[updateMFASoftwareTokenTask]()

func AddUpdateMFASoftwareTokenTask(ctx context.Context, sessionKey string, mfaType types.MFAType) (TaskResultChan, types.GenericError) {
	if err := updateMFASoftwareTokenTasksValidate(); err != nil {
		return nil, err
	}
	resultChan := make(TaskResultChan)
	updateMFASoftwareTokenTasks <- updateMFASoftwareTokenTask{sessionKey, mfaType, Task{ctx, resultChan}}
	return resultChan, nil
}

type verifyMFAUpdateTask struct {
	SessionKey string
	Code       string
	Task
}

var verifyMFAUpdateTasks, verifyMFAUpdateTasksValidate = createTaskChan[verifyMFAUpdateTask]()

func AddVerifyMFAUpdateTask(ctx context.Context, sessionKey string, code string) (TaskResultChan, types.GenericError) {
	if err := verifyMFAUpdateTasksValidate(); err != nil {
		return nil, err
	}
	resultChan := make(TaskResultChan)
	verifyMFAUpdateTasks <- verifyMFAUpdateTask{sessionKey, code, Task{ctx, resultChan}}
	return resultChan, nil
}

type selectMFATask struct {
	SessionKey string
	User       string
	MFAType    types.MFAType
	Task
}

var selectMFATasks, selectMFATasksValidate = createTaskChan[selectMFATask]()

func AddSelectMFATask(ctx context.Context, sessionKey string, user string, MFAType types.MFAType) (TaskResultChan, types.GenericError) {
	if err := selectMFATasksValidate(); err != nil {
		return nil, err
	}
	resultChan := make(TaskResultChan)
	selectMFATasks <- selectMFATask{sessionKey, user, MFAType, Task{ctx, resultChan}}
	return resultChan, nil
}

type initiatePasswordResetTask struct {
	Email string
	Task
}

var initiatePasswordResetTasks, initiatePasswordResetTasksValidate = createTaskChan[initiatePasswordResetTask]()

func AddInitiatePasswordResetTask(ctx context.Context, email string) (TaskResultChan, types.GenericError) {
	if err := initiatePasswordResetTasksValidate(); err != nil {
		return nil, err
	}
	resultChan := make(TaskResultChan)
	initiatePasswordResetTasks <- initiatePasswordResetTask{email, Task{ctx, resultChan}}
	return resultChan, nil
}

type resetPasswordTask struct {
	Token string
	Task
}

var resetPasswordTasks, resetPasswordTasksValidate = createTaskChan[resetPasswordTask]()

func AddResetPasswordTask(ctx context.Context, token string) (TaskResultChan, types.GenericError) {
	if err := resetPasswordTasksValidate(); err != nil {
		return nil, err
	}
	resultChan := make(TaskResultChan)
	resetPasswordTasks <- resetPasswordTask{token, Task{ctx, resultChan}}
	return resultChan, nil
}

type finalizePasswordResetTask struct {
	User     string
	Code     string
	Password string
	Task
}

var finalizePasswordResetTasks, finalizePasswordResetTasksValidate = createTaskChan[finalizePasswordResetTask]()

func AddFinalizePasswordResetTask(ctx context.Context, user string, code string, password string) (TaskResultChan, types.GenericError) {
	if err := finalizePasswordResetTasksValidate(); err != nil {
		return nil, err
	}
	resultChan := make(TaskResultChan)
	finalizePasswordResetTasks <- finalizePasswordResetTask{user, code, password, Task{ctx, resultChan}}
	return resultChan, nil
}

type unmaskTokenTask struct {
	Token string
	Task
}

var unmaskTokenTasks, unmaskTokenTasksValidate = createTaskChan[unmaskTokenTask]()

func AddUnmaskTokenTask(ctx context.Context, token string) (TaskResultChan, types.GenericError) {
	if err := unmaskTokenTasksValidate(); err != nil {
		return nil, err
	}
	resultChan := make(TaskResultChan)
	unmaskTokenTasks <- unmaskTokenTask{token, Task{ctx, resultChan}}
	return resultChan, nil
}

type getProfileTask struct {
	Task
}

var getProfileTasks, getProfileTasksValidate = createTaskChan[getProfileTask]()

func AddGetProfileTask(ctx context.Context) (TaskResultChan, types.GenericError) {
	if err := getProfileTasksValidate(); err != nil {
		return nil, err
	}
	resultChan := make(TaskResultChan)
	getProfileTasks <- getProfileTask{Task{ctx, resultChan}}
	return resultChan, nil
}
