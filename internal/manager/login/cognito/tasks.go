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

type withAuth struct {
	Auth any
}

type WithPayload interface {
	GetPayload() any
	SetPayload(any)
}

type withPayload struct {
	Payload any `json:"payload,omitempty"`
}

func (w *withPayload) GetPayload() any {
	return w.Payload
}

func (w *withPayload) SetPayload(i any) {
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

type withLoginSession struct {
	LoginSessionId string
}

type withCSRFToken struct {
	CSRFToken string
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
	Process(c *Cognito)
	fail(err types.GenericError)
}

// fail answers the task with err. It is used when processing panicked.
func (t Task[R, PR]) fail(err types.GenericError) {
	r := PR(new(R))
	r.SetError(err)
	t.ResultChan <- r
}

type appenderFunc[T processableTask] = func(T) types.GenericError

type doneFunc = func()

type counterFunc = func() int64

type taskWrapper struct {
	done doneFunc
	task processableTask
}

type taskAppenders struct {
	appendLoginStartTask                   appenderFunc[loginStartTask]
	appendUpdateSessionStartTask           appenderFunc[updateSessionStartTask]
	appendLoginTask                        appenderFunc[loginTask]
	appendExternalLoginTask                appenderFunc[externalLoginTask]
	appendMFASetupTask                     appenderFunc[mfaSetupTask]
	appendMFASetupVerifySoftwareTokenTask  appenderFunc[mfaSetupVerifySoftwareTokenTask]
	appendMFAVerifyTask                    appenderFunc[mfaVerifyTask]
	appendRefreshTokenTask                 appenderFunc[refreshTokenTask]
	appendLogOutTask                       appenderFunc[logOutTask]
	appendSatisfyPasswordUpdateRequestTask appenderFunc[satisfyPasswordUpdateRequestTask]
	appendUpdatePasswordTask               appenderFunc[updatePasswordTask]
	appendGetMFAStatusTask                 appenderFunc[getMFAStatusTask]
	appendUpdateMFASoftwareTokenTask       appenderFunc[updateMFASoftwareTokenTask]
	appendVerifyMFASoftwareTokenUpdateTask appenderFunc[verifyMFASoftwareTokenUpdateTask]
	appendSelectMFATask                    appenderFunc[selectMFATask]
	appendInitiatePasswordResetTask        appenderFunc[initiatePasswordResetTask]
	appendResetPasswordTask                appenderFunc[resetPasswordTask]
	appendFinalizePasswordResetTask        appenderFunc[finalizePasswordResetTask]
	appendUnmaskTokenTask                  appenderFunc[unmaskTokenTask]
	appendGetProfileTask                   appenderFunc[getProfileTask]
	appendTokenValidationTask              appenderFunc[tokenValidationTask]
}

func (c *Cognito) initTaskAppenders() {
	c.appendLoginStartTask, _ = newTaskAppendFunc[loginStartTask](c, 10000)
	c.appendUpdateSessionStartTask, _ = newTaskAppendFunc[updateSessionStartTask](c, 1000)
	c.appendLoginTask, _ = newTaskAppendFunc[loginTask](c, 10000)
	c.appendExternalLoginTask, _ = newTaskAppendFunc[externalLoginTask](c, 10000)
	c.appendMFASetupTask, _ = newTaskAppendFunc[mfaSetupTask](c, 1000)
	c.appendMFASetupVerifySoftwareTokenTask, _ = newTaskAppendFunc[mfaSetupVerifySoftwareTokenTask](c, 1000)
	c.appendMFAVerifyTask, _ = newTaskAppendFunc[mfaVerifyTask](c, 1000)
	c.appendRefreshTokenTask, _ = newTaskAppendFunc[refreshTokenTask](c, 1000)
	c.appendLogOutTask, _ = newTaskAppendFunc[logOutTask](c, 1000)
	c.appendSatisfyPasswordUpdateRequestTask, _ = newTaskAppendFunc[satisfyPasswordUpdateRequestTask](c, 1000)
	c.appendUpdatePasswordTask, _ = newTaskAppendFunc[updatePasswordTask](c, 1000)
	c.appendGetMFAStatusTask, _ = newTaskAppendFunc[getMFAStatusTask](c, 1000)
	c.appendUpdateMFASoftwareTokenTask, _ = newTaskAppendFunc[updateMFASoftwareTokenTask](c, 1000)
	c.appendVerifyMFASoftwareTokenUpdateTask, _ = newTaskAppendFunc[verifyMFASoftwareTokenUpdateTask](c, 1000)
	c.appendSelectMFATask, _ = newTaskAppendFunc[selectMFATask](c, 1000)
	c.appendInitiatePasswordResetTask, _ = newTaskAppendFunc[initiatePasswordResetTask](c, 1000)
	c.appendResetPasswordTask, _ = newTaskAppendFunc[resetPasswordTask](c, 1000)
	c.appendFinalizePasswordResetTask, _ = newTaskAppendFunc[finalizePasswordResetTask](c, 1000)
	c.appendUnmaskTokenTask, _ = newTaskAppendFunc[unmaskTokenTask](c, 1000)
	c.appendGetProfileTask, _ = newTaskAppendFunc[getProfileTask](c, 1000)
	c.appendTokenValidationTask, _ = newTaskAppendFunc[tokenValidationTask](c, 10000)
}

func newTaskAppendFunc[T processableTask](c *Cognito, taskLimit int64) (appenderFunc[T], counterFunc) {
	var counter int64 = 0
	lock := &sync.Mutex{}
	done := func() {
		atomic.AddInt64(&counter, -1)
	}
	return func(task T) types.GenericError {
			if taskLimit < 1 {
				c.tasks <- taskWrapper{nil, task}
				return nil
			}

			lock.Lock()
			defer lock.Unlock()

			if atomic.LoadInt64(&counter) >= taskLimit {
				return types.NewTooManyTasks(fmt.Sprint(task))
			}
			atomic.AddInt64(&counter, 1)
			c.tasks <- taskWrapper{done, task}
			return nil
		},
		func() int64 {
			return atomic.LoadInt64(&counter)
		}
}

type NextLoginStep struct {
	NextStep       NextStep `json:"next_step,omitempty" enum:"mfa_setup,mfa_software_token_setup_verify,mfa_select,mfa_software_token_verify,mfa_email_verify,mfa_sms_verify,new_password"`
	LoginSessionId string   `json:"login_session_id,omitempty"`
	withPayload
}

type AuthChallengeTaskResult interface {
	WithGenericError
	WithNextLoginStep
}

type AuthResultsData = any

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
