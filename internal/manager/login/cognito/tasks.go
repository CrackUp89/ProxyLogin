package cognito

import (
	"context"
	"fmt"
	"proxylogin/internal/manager/login/types"
	"sync"
	"sync/atomic"
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

type processableTask interface {
	Process()
}

type appenderFunc[T processableTask] = func(T) types.GenericError
type doneFunc = func()
type counterFunc = func() int64

type taskWrapper struct {
	done doneFunc
	task processableTask
}

var tasks = make(chan taskWrapper)

func newTaskAppendFunc[T processableTask](taskLimit int64) (appenderFunc[T], counterFunc) {
	var counter int64 = 0
	lock := &sync.Mutex{}
	done := func() {
		atomic.AddInt64(&counter, -1)
	}
	return func(task T) types.GenericError {
			if taskLimit < 1 {
				tasks <- taskWrapper{nil, task}
				return nil
			}

			lock.Lock()
			defer lock.Unlock()

			if atomic.LoadInt64(&counter) >= taskLimit {
				return types.NewTooManyTasks(fmt.Sprint(task))
			}
			atomic.AddInt64(&counter, 1)
			tasks <- taskWrapper{done, task}
			return nil
		},
		func() int64 {
			return atomic.LoadInt64(&counter)
		}
}

// ---------------------------------------------------------------------------
// loginTask
// ---------------------------------------------------------------------------

type loginTask struct {
	SessionKey   string
	User         string
	Password     string
	RememberUser bool
	Task
}

func (t loginTask) Process() {
	processLoginTask(t)
}

var appendLoginTask, _ = newTaskAppendFunc[loginTask](10000)

func createLoginTask(ctx context.Context, sessionKey string, user string, password string, rememberUser bool) (TaskResultChan, types.GenericError) {
	resultChan := make(TaskResultChan)
	err := appendLoginTask(loginTask{sessionKey, user, password, rememberUser, Task{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// mfaSetupTask
// ---------------------------------------------------------------------------

type mfaSetupTask struct {
	SessionKey string
	User       string
	MFAType    types.MFAType
	Task
}

func (t mfaSetupTask) Process() {
	processMFASetupTask(t)
}

var appendMFASetupTask, _ = newTaskAppendFunc[mfaSetupTask](1000)

func createMFASetupTask(ctx context.Context, sessionKey string, user string, setupType types.MFAType) (TaskResultChan, types.GenericError) {
	resultChan := make(TaskResultChan)
	err := appendMFASetupTask(mfaSetupTask{sessionKey, user, setupType, Task{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// mfaSetupVerifySoftwareTokenTask
// ---------------------------------------------------------------------------

type mfaSetupVerifySoftwareTokenTask struct {
	SessionKey string
	User       string
	Code       string
	Task
}

func (t mfaSetupVerifySoftwareTokenTask) Process() {
	processMFASetupVerifySoftwareTokenTask(t)
}

var appendMFASetupVerifySoftwareTokenTask, _ = newTaskAppendFunc[mfaSetupVerifySoftwareTokenTask](1000)

func createMFASetupVerifySoftwareTokenTask(ctx context.Context, sessionKey string, user string, code string) (TaskResultChan, types.GenericError) {
	resultChan := make(TaskResultChan)
	err := appendMFASetupVerifySoftwareTokenTask(mfaSetupVerifySoftwareTokenTask{sessionKey, user, code, Task{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// mfaVerifyTask
// ---------------------------------------------------------------------------

type mfaVerifyTask struct {
	SessionKey string
	User       string
	Code       string
	Task
}

func (t mfaVerifyTask) Process() {
	processMFAVerifyTask(t)
}

var appendMFAVerifyTask, _ = newTaskAppendFunc[mfaVerifyTask](1000)

func createMFAVerifyTask(ctx context.Context, sessionKey string, user string, code string) (TaskResultChan, types.GenericError) {
	resultChan := make(TaskResultChan)
	err := appendMFAVerifyTask(mfaVerifyTask{sessionKey, user, code, Task{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// refreshTokenTask
// ---------------------------------------------------------------------------

type refreshTokenTask struct {
	User         string
	RefreshToken string
	Remember     bool
	Task
}

func (t refreshTokenTask) Process() {
	processRefreshTokenTask(t)
}

var appendRefreshTokenTask, _ = newTaskAppendFunc[refreshTokenTask](1000)

func createRefreshTokenTask(ctx context.Context, user string, refreshToken string, remember bool) (TaskResultChan, types.GenericError) {
	resultChan := make(TaskResultChan)
	err := appendRefreshTokenTask(refreshTokenTask{user, refreshToken, remember, Task{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// logOutTask
// ---------------------------------------------------------------------------

type logOutTask struct {
	RefreshToken string
	Task
}

func (t logOutTask) Process() {
	processLogOutTask(t)
}

var appendLogOutTask, _ = newTaskAppendFunc[logOutTask](1000)

func createLogOutTask(ctx context.Context, refreshToken string) (TaskResultChan, types.GenericError) {
	resultChan := make(TaskResultChan)
	err := appendLogOutTask(logOutTask{refreshToken, Task{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// satisfyPasswordUpdateRequestTask
// ---------------------------------------------------------------------------

type satisfyPasswordUpdateRequestTask struct {
	SessionKey string
	User       string
	Password   string
	Attributes map[string]string
	Task
}

func (t satisfyPasswordUpdateRequestTask) Process() {
	processSatisfyPasswordUpdateRequestTask(t)
}

var appendSatisfyPasswordUpdateRequestTask, _ = newTaskAppendFunc[satisfyPasswordUpdateRequestTask](1000)

func createSatisfyPasswordUpdateRequestTask(ctx context.Context, sessionKey string, user string, password string, attributes map[string]string) (TaskResultChan, types.GenericError) {
	resultChan := make(TaskResultChan)
	err := appendSatisfyPasswordUpdateRequestTask(satisfyPasswordUpdateRequestTask{sessionKey, user, password, attributes, Task{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// updatePasswordTask
// ---------------------------------------------------------------------------

type updatePasswordTask struct {
	CurrentPassword string
	NewPassword     string
	Task
}

func (t updatePasswordTask) Process() {
	processUpdatePasswordTask(t)
}

var appendUpdatePasswordTask, _ = newTaskAppendFunc[updatePasswordTask](1000)

func createUpdatePasswordTask(ctx context.Context, currentPassword string, newPassword string) (TaskResultChan, types.GenericError) {
	resultChan := make(TaskResultChan)
	err := appendUpdatePasswordTask(updatePasswordTask{currentPassword, newPassword, Task{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// getMFAStatusTask
// ---------------------------------------------------------------------------

type getMFAStatusTask struct {
	Task
}

func (t getMFAStatusTask) Process() {
	processGetMFAStatusTask(t)
}

var appendGetMFAStatusTask, _ = newTaskAppendFunc[getMFAStatusTask](1000)

func createGetMFAStatusTask(ctx context.Context) (TaskResultChan, types.GenericError) {
	resultChan := make(TaskResultChan)
	err := appendGetMFAStatusTask(getMFAStatusTask{Task{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// updateMFASoftwareTokenTask
// ---------------------------------------------------------------------------

type updateMFASoftwareTokenTask struct {
	SessionKey string
	MFAType    types.MFAType
	Task
}

func (t updateMFASoftwareTokenTask) Process() {
	processUpdateMFASoftwareTokenTask(t)
}

var appendUpdateMFASoftwareTokenTask, _ = newTaskAppendFunc[updateMFASoftwareTokenTask](1000)

func createUpdateMFASoftwareTokenTask(ctx context.Context, sessionKey string, mfaType types.MFAType) (TaskResultChan, types.GenericError) {
	resultChan := make(TaskResultChan)
	err := appendUpdateMFASoftwareTokenTask(updateMFASoftwareTokenTask{sessionKey, mfaType, Task{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// verifyMFAUpdateTask
// ---------------------------------------------------------------------------

type verifyMFAUpdateTask struct {
	SessionKey string
	Code       string
	Task
}

func (t verifyMFAUpdateTask) Process() {
	processVerifyMFAUpdateTask(t)
}

var appendVerifyMFAUpdateTask, _ = newTaskAppendFunc[verifyMFAUpdateTask](1000)

func createVerifyMFAUpdateTask(ctx context.Context, sessionKey string, code string) (TaskResultChan, types.GenericError) {
	resultChan := make(TaskResultChan)
	err := appendVerifyMFAUpdateTask(verifyMFAUpdateTask{sessionKey, code, Task{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// selectMFATask
// ---------------------------------------------------------------------------

type selectMFATask struct {
	SessionKey string
	User       string
	MFAType    types.MFAType
	Task
}

func (t selectMFATask) Process() {
	processSelectMFATask(t)
}

var appendSelectMFATask, _ = newTaskAppendFunc[selectMFATask](1000)

func createSelectMFATask(ctx context.Context, sessionKey string, user string, mfaType types.MFAType) (TaskResultChan, types.GenericError) {
	resultChan := make(TaskResultChan)
	err := appendSelectMFATask(selectMFATask{sessionKey, user, mfaType, Task{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// initiatePasswordResetTask
// ---------------------------------------------------------------------------

type initiatePasswordResetTask struct {
	Email string
	Task
}

func (t initiatePasswordResetTask) Process() {
	processInitiatePasswordResetTask(t)
}

var appendInitiatePasswordResetTask, _ = newTaskAppendFunc[initiatePasswordResetTask](1000)

func createInitiatePasswordResetTask(ctx context.Context, email string) (TaskResultChan, types.GenericError) {
	resultChan := make(TaskResultChan)
	err := appendInitiatePasswordResetTask(initiatePasswordResetTask{email, Task{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// resetPasswordTask
// ---------------------------------------------------------------------------

type resetPasswordTask struct {
	Token string
	Task
}

func (t resetPasswordTask) Process() {
	processResetPasswordTask(t)
}

var appendResetPasswordTask, _ = newTaskAppendFunc[resetPasswordTask](1000)

func createResetPasswordTask(ctx context.Context, token string) (TaskResultChan, types.GenericError) {
	resultChan := make(TaskResultChan)
	err := appendResetPasswordTask(resetPasswordTask{token, Task{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// finalizePasswordResetTask
// ---------------------------------------------------------------------------

type finalizePasswordResetTask struct {
	User     string
	Code     string
	Password string
	Task
}

func (t finalizePasswordResetTask) Process() {
	processFinalizePasswordResetTask(t)
}

var appendFinalizePasswordResetTask, _ = newTaskAppendFunc[finalizePasswordResetTask](1000)

func createFinalizePasswordResetTask(ctx context.Context, user string, code string, password string) (TaskResultChan, types.GenericError) {
	resultChan := make(TaskResultChan)
	err := appendFinalizePasswordResetTask(finalizePasswordResetTask{user, code, password, Task{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// unmaskTokenTask
// ---------------------------------------------------------------------------

type unmaskTokenTask struct {
	Token string
	Task
}

func (t unmaskTokenTask) Process() {
	processUnmaskTokenTask(t)
}

var appendUnmaskTokenTask, _ = newTaskAppendFunc[unmaskTokenTask](1000)

func createUnmaskTokenTask(ctx context.Context, token string) (TaskResultChan, types.GenericError) {
	resultChan := make(TaskResultChan)
	err := appendUnmaskTokenTask(unmaskTokenTask{token, Task{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// getProfileTask
// ---------------------------------------------------------------------------

type getProfileTask struct {
	Task
}

func (t getProfileTask) Process() {
	processGetProfileTask(t)
}

var appendGetProfileTask, _ = newTaskAppendFunc[getProfileTask](1000)

func createGetProfileTask(ctx context.Context) (TaskResultChan, types.GenericError) {
	resultChan := make(TaskResultChan)
	err := appendGetProfileTask(getProfileTask{Task{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}
