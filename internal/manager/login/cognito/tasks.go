package cognito

import (
	"context"
	"fmt"
	"proxylogin/internal/manager/login/types"
	"sync"
	"sync/atomic"
)

type WithGenericError interface {
	GetError() types.GenericError
	SetError(types.GenericError)
}

type WithSession interface {
	GetSession() string
	SetSession(string)
}

type WithNextStep interface {
	GetNextStep() NextStep
	SetNextStep(NextStep)
}

type WithPayload interface {
	GetPayload() interface{}
	SetPayload(interface{})
}

type withPayload struct {
	Payload interface{} `json:"payload,omitempty"`
}

func (w *withPayload) GetPayload() interface{} {
	return w.Payload
}

func (w *withPayload) SetPayload(i interface{}) {
	w.Payload = i
}

type Task[R any, PR interface {
	*R
	WithTaskResultBase
}] struct {
	Context    context.Context
	ResultChan chan PR
}

type SideEffectType string

const (
	LogOutSideEffect SideEffectType = "logOut"
)

type SideEffect interface {
	GetType() SideEffectType
}

type SideEffectOutput struct {
	Type SideEffectType
}

func (s SideEffectOutput) GetType() SideEffectType {
	return s.Type
}

type WithSideEffects interface {
	GetSideEffects() []SideEffect
	SetSideEffects(sideEffect []SideEffect)
	AddSideEffects(sideEffects []SideEffect)
	AddSideEffect(sideEffect SideEffect)
	HasSideEffect(name SideEffectType) bool
}

type WithTaskResultBase interface {
	WithGenericError
	WithSideEffects
}

type withResultBase struct {
	Err         types.GenericError
	SideEffects []SideEffect
}

func (t *withResultBase) GetSideEffects() []SideEffect {
	return t.SideEffects
}

func (t *withResultBase) SetSideEffects(sideEffect []SideEffect) {
	t.SideEffects = sideEffect
}

func (t *withResultBase) AddSideEffects(sideEffects []SideEffect) {
	t.SideEffects = append(t.SideEffects, sideEffects...)
}

func (t *withResultBase) AddSideEffect(sideEffect SideEffect) {
	t.SideEffects = append(t.SideEffects, sideEffect)
}

func (t *withResultBase) HasSideEffect(name SideEffectType) bool {
	for _, sideEffect := range t.SideEffects {
		if sideEffect.GetType() == name {
			return true
		}
	}
	return false
}

func (t *withResultBase) SetError(genericError types.GenericError) {
	t.Err = genericError
}

func (t *withResultBase) GetError() types.GenericError {
	return t.Err
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

type NextLoginStep struct {
	Step    NextStep `json:"step,omitempty" enum:"mfa_setup,mfa_software_token_setup_verify,mfa_select,mfa_software_token_verify,mfa_email_verify,mfa_sms_verify,new_password"`
	Session string   `json:"session,omitempty"`
	withPayload
}

func (l *NextLoginStep) GetSession() string {
	return l.Session
}

func (l *NextLoginStep) SetSession(s string) {
	l.Session = s
}

func (l *NextLoginStep) GetNextStep() NextStep {
	return l.Step
}

func (l *NextLoginStep) SetNextStep(step NextStep) {
	l.Step = step
}

type AuthChallengeTaskResult interface {
	WithGenericError
	WithNextLoginStep
}

type AuthResultsData = interface{}

type AuthResults interface {
	GetAuthResultsData() AuthResultsData
	SetAuthResultsData(AuthResultsData)
	GetRemember() bool
	SetRemember(bool)
}

type WithAuthResults interface {
	GetAuthResults() AuthResults
	SetAuthResults(AuthResults)
}

type AuthTaskResult interface {
	WithGenericError
	WithAuthResults
}

type WithNextLoginStep interface {
	GetNextLoginStep() *NextLoginStep
	SetNextLoginStep(*NextLoginStep)
}
type withNextLoginStep struct {
	nextLoginStep *NextLoginStep
}

func (w *withNextLoginStep) GetNextLoginStep() *NextLoginStep {
	return w.nextLoginStep
}

func (w *withNextLoginStep) SetNextLoginStep(nextLoginStep *NextLoginStep) {
	w.nextLoginStep = nextLoginStep
}

type authResults struct {
	authResultsData AuthResultsData
	remember        bool
}

func (a *authResults) GetAuthResultsData() AuthResultsData {
	return a.authResultsData
}

func (a *authResults) SetAuthResultsData(data AuthResultsData) {
	a.authResultsData = data
}

func (a *authResults) GetRemember() bool {
	return a.remember
}

func (a *authResults) SetRemember(b bool) {
	a.remember = b
}

type withAuthResults struct {
	authResults AuthResults
}

func (w *withAuthResults) GetAuthResults() AuthResults {
	return w.authResults
}

func (w *withAuthResults) SetAuthResults(results AuthResults) {
	w.authResults = results
}

type LoginFinalStepResult interface {
	WithTaskResultBase
	WithAuthResults
}

type LoginStepResult interface {
	WithTaskResultBase
	WithNextLoginStep
	WithAuthResults
}

type loginStepResult struct {
	withResultBase
	withNextLoginStep
	withAuthResults
}

type TaskResult interface {
	WithTaskResultBase
	WithPayload
}

// ---------------------------------------------------------------------------
// loginTask
// ---------------------------------------------------------------------------

type loginTaskResultChan chan *loginStepResult

type loginTask struct {
	SessionKey   string
	User         string
	Password     string
	RememberUser bool
	Task[loginStepResult, *loginStepResult]
}

func (t loginTask) Process() {
	t.ResultChan <- processLoginTask(t)
}

var appendLoginTask, _ = newTaskAppendFunc[loginTask](10000)

func createLoginTask(ctx context.Context, sessionKey string, user string, password string, rememberUser bool) (loginTaskResultChan, types.GenericError) {
	resultChan := make(loginTaskResultChan)
	err := appendLoginTask(loginTask{sessionKey, user, password, rememberUser, Task[loginStepResult, *loginStepResult]{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// mfaSetupTask
// ---------------------------------------------------------------------------

type mfaSetupTaskResult loginStepResult

type mfaSetupTaskResultChan chan *mfaSetupTaskResult

type mfaSetupTask struct {
	SessionKey string
	User       string
	MFAType    types.MFAType
	Task[mfaSetupTaskResult, *mfaSetupTaskResult]
}

func (t mfaSetupTask) Process() {
	t.ResultChan <- processMFASetupTask(t)
}

var appendMFASetupTask, _ = newTaskAppendFunc[mfaSetupTask](1000)

func createMFASetupTask(ctx context.Context, sessionKey string, user string, setupType types.MFAType) (mfaSetupTaskResultChan, types.GenericError) {
	resultChan := make(mfaSetupTaskResultChan)
	err := appendMFASetupTask(mfaSetupTask{sessionKey, user, setupType, Task[mfaSetupTaskResult, *mfaSetupTaskResult]{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// mfaSetupVerifySoftwareTokenTask
// ---------------------------------------------------------------------------

type mfaSetupVerifySoftwareTokenTaskResult loginStepResult

type mfaSetupVerifySoftwareTokenTaskResultChan chan *mfaSetupVerifySoftwareTokenTaskResult

type mfaSetupVerifySoftwareTokenTask struct {
	SessionKey string
	User       string
	Code       string
	Task[mfaSetupVerifySoftwareTokenTaskResult, *mfaSetupVerifySoftwareTokenTaskResult]
}

func (t mfaSetupVerifySoftwareTokenTask) Process() {
	t.ResultChan <- processMFASetupVerifySoftwareTokenTask(t)
}

var appendMFASetupVerifySoftwareTokenTask, _ = newTaskAppendFunc[mfaSetupVerifySoftwareTokenTask](1000)

func createMFASetupVerifySoftwareTokenTask(ctx context.Context, sessionKey string, user string, code string) (mfaSetupVerifySoftwareTokenTaskResultChan, types.GenericError) {
	resultChan := make(mfaSetupVerifySoftwareTokenTaskResultChan)
	err := appendMFASetupVerifySoftwareTokenTask(mfaSetupVerifySoftwareTokenTask{sessionKey, user, code, Task[mfaSetupVerifySoftwareTokenTaskResult, *mfaSetupVerifySoftwareTokenTaskResult]{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// mfaVerifyTask
// ---------------------------------------------------------------------------

type mfaVerifyTaskResult loginStepResult

type mfaVerifyTaskResultChan chan *mfaVerifyTaskResult

type mfaVerifyTask struct {
	SessionKey string
	User       string
	Code       string
	Task[mfaVerifyTaskResult, *mfaVerifyTaskResult]
}

func (t mfaVerifyTask) Process() {
	t.ResultChan <- processMFAVerifyTask(t)
}

var appendMFAVerifyTask, _ = newTaskAppendFunc[mfaVerifyTask](1000)

func createMFAVerifyTask(ctx context.Context, sessionKey string, user string, code string) (mfaVerifyTaskResultChan, types.GenericError) {
	resultChan := make(mfaVerifyTaskResultChan)
	err := appendMFAVerifyTask(mfaVerifyTask{sessionKey, user, code, Task[mfaVerifyTaskResult, *mfaVerifyTaskResult]{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// refreshTokenTask
// ---------------------------------------------------------------------------

type refreshTokenTaskResult struct {
	withResultBase
	withAuthResults
}

type refreshTokenTaskResultChan chan *refreshTokenTaskResult

type refreshTokenTask struct {
	User         string
	RefreshToken string
	Remember     bool
	Task[refreshTokenTaskResult, *refreshTokenTaskResult]
}

func (t refreshTokenTask) Process() {
	t.ResultChan <- processRefreshTokenTask(t)
}

var appendRefreshTokenTask, _ = newTaskAppendFunc[refreshTokenTask](1000)

func createRefreshTokenTask(ctx context.Context, user string, refreshToken string, remember bool) (refreshTokenTaskResultChan, types.GenericError) {
	resultChan := make(refreshTokenTaskResultChan)
	err := appendRefreshTokenTask(refreshTokenTask{user, refreshToken, remember, Task[refreshTokenTaskResult, *refreshTokenTaskResult]{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// logOutTask
// ---------------------------------------------------------------------------

type logOutTaskResult struct {
	withResultBase
	withPayload
}

type logOutTaskResultChan chan *logOutTaskResult

type logOutTask struct {
	RefreshToken string
	Task[logOutTaskResult, *logOutTaskResult]
}

func (t logOutTask) Process() {
	t.ResultChan <- processLogOutTask(t)
}

var appendLogOutTask, _ = newTaskAppendFunc[logOutTask](1000)

func createLogOutTask(ctx context.Context, refreshToken string) (logOutTaskResultChan, types.GenericError) {
	resultChan := make(logOutTaskResultChan)
	err := appendLogOutTask(logOutTask{refreshToken, Task[logOutTaskResult, *logOutTaskResult]{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// satisfyPasswordUpdateRequestTask
// ---------------------------------------------------------------------------

type satisfyPasswordUpdateRequestTaskResult loginStepResult

type satisfyPasswordUpdateRequestTaskResultChan chan *satisfyPasswordUpdateRequestTaskResult

type satisfyPasswordUpdateRequestTask struct {
	SessionKey string
	User       string
	Password   string
	Attributes map[string]string
	Task[satisfyPasswordUpdateRequestTaskResult, *satisfyPasswordUpdateRequestTaskResult]
}

func (t satisfyPasswordUpdateRequestTask) Process() {
	t.ResultChan <- processSatisfyPasswordUpdateRequestTask(t)
}

var appendSatisfyPasswordUpdateRequestTask, _ = newTaskAppendFunc[satisfyPasswordUpdateRequestTask](1000)

func createSatisfyPasswordUpdateRequestTask(ctx context.Context, sessionKey string, user string, password string, attributes map[string]string) (satisfyPasswordUpdateRequestTaskResultChan, types.GenericError) {
	resultChan := make(satisfyPasswordUpdateRequestTaskResultChan)
	err := appendSatisfyPasswordUpdateRequestTask(
		satisfyPasswordUpdateRequestTask{sessionKey, user, password, attributes,
			Task[satisfyPasswordUpdateRequestTaskResult, *satisfyPasswordUpdateRequestTaskResult]{ctx, resultChan},
		})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// updatePasswordTask
// ---------------------------------------------------------------------------

type updatePasswordTaskResult struct {
	withResultBase
	withPayload
}

type updatePasswordTaskResultChan chan *updatePasswordTaskResult

type updatePasswordTask struct {
	CurrentPassword string
	NewPassword     string
	Task[updatePasswordTaskResult, *updatePasswordTaskResult]
}

func (t updatePasswordTask) Process() {
	t.ResultChan <- processUpdatePasswordTask(t)
}

var appendUpdatePasswordTask, _ = newTaskAppendFunc[updatePasswordTask](1000)

func createUpdatePasswordTask(ctx context.Context, currentPassword string, newPassword string) (updatePasswordTaskResultChan, types.GenericError) {
	resultChan := make(updatePasswordTaskResultChan)
	err := appendUpdatePasswordTask(updatePasswordTask{currentPassword, newPassword,
		Task[updatePasswordTaskResult, *updatePasswordTaskResult]{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// getMFAStatusTask
// ---------------------------------------------------------------------------

type getMFAStatusTaskResult struct {
	withResultBase
	status *types.MFAStatus
}

func (g *getMFAStatusTaskResult) GetPayload() interface{} {
	return g.status
}

func (g *getMFAStatusTaskResult) SetPayload(_ interface{}) {
	panic("should not be called")
}

type getMFAStatusTaskResultChan chan *getMFAStatusTaskResult

type getMFAStatusTask struct {
	Task[getMFAStatusTaskResult, *getMFAStatusTaskResult]
}

func (t getMFAStatusTask) Process() {
	t.ResultChan <- processGetMFAStatusTask(t)
}

var appendGetMFAStatusTask, _ = newTaskAppendFunc[getMFAStatusTask](1000)

func createGetMFAStatusTask(ctx context.Context) (getMFAStatusTaskResultChan, types.GenericError) {
	resultChan := make(getMFAStatusTaskResultChan)
	err := appendGetMFAStatusTask(getMFAStatusTask{Task[getMFAStatusTaskResult, *getMFAStatusTaskResult]{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// updateMFASoftwareTokenTask
// ---------------------------------------------------------------------------

type updateMFASoftwareTokenTaskResultPayload struct {
	Code *string `json:"code"`
}

type updateMFASoftwareTokenTaskResult struct {
	withResultBase
	payload *updateMFASoftwareTokenTaskResultPayload
}

func (u *updateMFASoftwareTokenTaskResult) GetPayload() interface{} {
	return u.payload
}

func (u *updateMFASoftwareTokenTaskResult) SetPayload(_ interface{}) {
	panic("should not be called")
}

type updateMFASoftwareTokenTaskResultChan chan *updateMFASoftwareTokenTaskResult

type updateMFASoftwareTokenTask struct {
	MFAType types.MFAType
	Task[updateMFASoftwareTokenTaskResult, *updateMFASoftwareTokenTaskResult]
}

func (t updateMFASoftwareTokenTask) Process() {
	t.ResultChan <- processUpdateMFASoftwareTokenTask(t)
}

var appendUpdateMFASoftwareTokenTask, _ = newTaskAppendFunc[updateMFASoftwareTokenTask](1000)

func createUpdateMFASoftwareTokenTask(ctx context.Context, mfaType types.MFAType) (updateMFASoftwareTokenTaskResultChan, types.GenericError) {
	resultChan := make(updateMFASoftwareTokenTaskResultChan)
	err := appendUpdateMFASoftwareTokenTask(updateMFASoftwareTokenTask{mfaType, Task[updateMFASoftwareTokenTaskResult, *updateMFASoftwareTokenTaskResult]{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// verifyMFAUpdateTask
// ---------------------------------------------------------------------------

type verifyMFAUpdateTaskResult struct {
	withResultBase
	withPayload
}

type verifyMFAUpdateTaskResultChan chan *verifyMFAUpdateTaskResult

type verifyMFAUpdateTask struct {
	Code string
	Task[verifyMFAUpdateTaskResult, *verifyMFAUpdateTaskResult]
}

func (t verifyMFAUpdateTask) Process() {
	t.ResultChan <- processVerifyMFAUpdateTask(t)
}

var appendVerifyMFAUpdateTask, _ = newTaskAppendFunc[verifyMFAUpdateTask](1000)

func createVerifyMFAUpdateTask(ctx context.Context, code string) (verifyMFAUpdateTaskResultChan, types.GenericError) {
	resultChan := make(verifyMFAUpdateTaskResultChan)
	err := appendVerifyMFAUpdateTask(verifyMFAUpdateTask{code, Task[verifyMFAUpdateTaskResult, *verifyMFAUpdateTaskResult]{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// selectMFATask
// ---------------------------------------------------------------------------

type selectMFATaskResult loginStepResult

type selectMFATaskResultChan chan *selectMFATaskResult

type selectMFATask struct {
	SessionKey string
	User       string
	MFAType    types.MFAType
	Task[selectMFATaskResult, *selectMFATaskResult]
}

func (t selectMFATask) Process() {
	t.ResultChan <- processSelectMFATask(t)
}

var appendSelectMFATask, _ = newTaskAppendFunc[selectMFATask](1000)

func createSelectMFATask(ctx context.Context, sessionKey string, user string, mfaType types.MFAType) (selectMFATaskResultChan, types.GenericError) {
	resultChan := make(selectMFATaskResultChan)
	err := appendSelectMFATask(selectMFATask{sessionKey, user, mfaType, Task[selectMFATaskResult, *selectMFATaskResult]{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// initiatePasswordResetTask
// ---------------------------------------------------------------------------

type initiatePasswordResetTaskResult struct {
	withResultBase
	withPayload
}

type initiatePasswordResetTaskResultChan chan *initiatePasswordResetTaskResult

type initiatePasswordResetTask struct {
	Email string
	Task[initiatePasswordResetTaskResult, *initiatePasswordResetTaskResult]
}

func (t initiatePasswordResetTask) Process() {
	t.ResultChan <- processInitiatePasswordResetTask(t)
}

var appendInitiatePasswordResetTask, _ = newTaskAppendFunc[initiatePasswordResetTask](1000)

func createInitiatePasswordResetTask(ctx context.Context, email string) (initiatePasswordResetTaskResultChan, types.GenericError) {
	resultChan := make(initiatePasswordResetTaskResultChan)
	err := appendInitiatePasswordResetTask(initiatePasswordResetTask{email, Task[initiatePasswordResetTaskResult, *initiatePasswordResetTaskResult]{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// resetPasswordTask
// ---------------------------------------------------------------------------

type resetPasswordTaskResult struct {
	withResultBase
	redirectTo string
}

type resetPasswordTaskResultChan chan *resetPasswordTaskResult

type resetPasswordTask struct {
	Token string
	Task[resetPasswordTaskResult, *resetPasswordTaskResult]
}

func (t resetPasswordTask) Process() {
	t.ResultChan <- processResetPasswordTask(t)
}

var appendResetPasswordTask, _ = newTaskAppendFunc[resetPasswordTask](1000)

func createResetPasswordTask(ctx context.Context, token string) (resetPasswordTaskResultChan, types.GenericError) {
	resultChan := make(resetPasswordTaskResultChan)
	err := appendResetPasswordTask(resetPasswordTask{token, Task[resetPasswordTaskResult, *resetPasswordTaskResult]{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// finalizePasswordResetTask
// ---------------------------------------------------------------------------

type finalizePasswordResetTaskResult struct {
	withResultBase
	withPayload
}

type finalizePasswordResetTaskResultChan chan *finalizePasswordResetTaskResult

type finalizePasswordResetTask struct {
	Token    string
	Code     string
	Password string
	Task[finalizePasswordResetTaskResult, *finalizePasswordResetTaskResult]
}

func (t finalizePasswordResetTask) Process() {
	t.ResultChan <- processFinalizePasswordResetTask(t)
}

var appendFinalizePasswordResetTask, _ = newTaskAppendFunc[finalizePasswordResetTask](1000)

func createFinalizePasswordResetTask(ctx context.Context, token string, code string, password string) (finalizePasswordResetTaskResultChan, types.GenericError) {
	resultChan := make(finalizePasswordResetTaskResultChan)
	err := appendFinalizePasswordResetTask(finalizePasswordResetTask{token, code, password, Task[finalizePasswordResetTaskResult, *finalizePasswordResetTaskResult]{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// unmaskTokenTask
// ---------------------------------------------------------------------------

type unmaskTokenTaskResult struct {
	withResultBase
	withAuthResults
}

func (u *unmaskTokenTaskResult) GetPayload() interface{} {
	return u.authResults
}

func (u *unmaskTokenTaskResult) SetPayload(_ interface{}) {
	panic("should not be called")
}

type unmaskTokenTaskResultChan chan *unmaskTokenTaskResult

type unmaskTokenTask struct {
	Token string
	Task[unmaskTokenTaskResult, *unmaskTokenTaskResult]
}

func (t unmaskTokenTask) Process() {
	t.ResultChan <- processUnmaskTokenTask(t)
}

var appendUnmaskTokenTask, _ = newTaskAppendFunc[unmaskTokenTask](1000)

func createUnmaskTokenTask(ctx context.Context, token string) (unmaskTokenTaskResultChan, types.GenericError) {
	resultChan := make(unmaskTokenTaskResultChan)
	err := appendUnmaskTokenTask(unmaskTokenTask{token, Task[unmaskTokenTaskResult, *unmaskTokenTaskResult]{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// getProfileTask
// ---------------------------------------------------------------------------

type getProfileTaskResult struct {
	withResultBase
	Profile *UserIdTokenProfile
}

func (g *getProfileTaskResult) GetPayload() interface{} {
	return g.Profile
}

func (g *getProfileTaskResult) SetPayload(_ interface{}) {
	panic("should not be called")
}

type getProfileTaskResultChan chan *getProfileTaskResult

type getProfileTask struct {
	Task[getProfileTaskResult, *getProfileTaskResult]
}

func (t getProfileTask) Process() {
	t.ResultChan <- processGetProfileTask(t)
}

var appendGetProfileTask, _ = newTaskAppendFunc[getProfileTask](1000)

func createGetProfileTask(ctx context.Context) (getProfileTaskResultChan, types.GenericError) {
	resultChan := make(getProfileTaskResultChan)
	err := appendGetProfileTask(getProfileTask{Task[getProfileTaskResult, *getProfileTaskResult]{ctx, resultChan}})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}

// ---------------------------------------------------------------------------
// validationTask
// ---------------------------------------------------------------------------

type tokenValidationTaskResult struct {
	withResultBase
	Validity         map[string]bool
	ValidationErrors map[string]string
}

type tokenValidationTaskResultChan chan *tokenValidationTaskResult

type tokenValidationTask struct {
	Tokens map[string]string
	Task[tokenValidationTaskResult, *tokenValidationTaskResult]
}

func (t tokenValidationTask) Process() {
	t.ResultChan <- processValidateTask(t)
}

var appendTokenValidationTask, _ = newTaskAppendFunc[tokenValidationTask](10000)

func createTokenValidationTask(ctx context.Context, tokens map[string]string) (tokenValidationTaskResultChan, types.GenericError) {
	resultChan := make(tokenValidationTaskResultChan)
	err := appendTokenValidationTask(tokenValidationTask{
		tokens,
		Task[tokenValidationTaskResult, *tokenValidationTaskResult]{ctx, resultChan},
	})
	if err != nil {
		return nil, err
	}
	return resultChan, nil
}
