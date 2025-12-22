package cognito

import (
	"fmt"
	"proxylogin/internal/manager/tools"
	"reflect"
	"sync"
	"time"

	"go.uber.org/zap"
)

var sessionsLogger *zap.Logger

func getSessionsLogger() *zap.Logger {
	if sessionsLogger == nil {
		sessionsLogger = getLogger().Named("sessions")
	}
	return sessionsLogger
}

type NextStep string

const (
	NextStepNone                        NextStep = ""
	NextStepMFASetup                    NextStep = "mfa_setup"
	NextStepMFASoftwareTokenSetupVerify NextStep = "mfa_software_token_setup_verify"
	NextStepMFASelect                   NextStep = "mfa_select"
	NextStepMFASoftwareTokenVerify      NextStep = "mfa_software_token_verify"
	NextStepMFAEMailVerify              NextStep = "mfa_email_verify"
	NextStepMFASMSVerify                NextStep = "mfa_sms_verify"
	NextStepNewPassword                 NextStep = "new_password"
)

func (s NextStep) String() string {
	return string(s)
}

type withValidityTimeframe interface {
	GetStartTime() time.Time
	GetExpirationTime() time.Time
}

func cleanupExpiredSessions[T withValidityTimeframe](sessions *sync.Map) {
	sessions.Range(func(k, v interface{}) bool {
		session := v.(T)
		if session.GetStartTime().After(time.Now()) {
			getSessionsLogger().Info("session expired",
				zap.String("session", k.(string)),
				zap.String("type", fmt.Sprint(reflect.TypeOf(session))))
			sessions.Delete(k)
		}
		return true
	})
}

func StartSessionCleanupRoutine() func() {
	stop := make(chan bool, 1)
	go func() {
		cleanup := time.NewTicker(15 * time.Second)
		for {
			select {
			case <-cleanup.C:
				cleanupExpiredSessions[LoginSession](activeLoginSessions)
				cleanupExpiredSessions[*initiateResetPasswordSession](activeInitiateResetPasswordSessions)
			case <-stop:
				getSessionsLogger().Info("Session cleanup routine stopped")
				return
			}
		}
	}()
	return func() {
		stop <- true
	}
}

var loginSessionMutexManager = tools.NamedMutexManager{}

func lockLoginSession(sessionKey string) func() {
	if sessionKey == "" {
		return func() {
			getSessionsLogger().Warn("can not lock session - session key is empty", zap.Stack("stack"))
		}
	}
	lock := loginSessionMutexManager.GetNamedMutex(sessionKey)
	lock.Lock()
	return func() { lock.Unlock() }
}

type LoginSession struct {
	cognitoSession string
	created        time.Time
	expires        time.Time
	nextStep       NextStep
	tag            interface{}
}

func (l LoginSession) GetStartTime() time.Time {
	return l.created
}

func (l LoginSession) GetExpirationTime() time.Time {
	return l.expires
}

var activeLoginSessions = new(sync.Map)

func getLoginSession(loginSession string) (LoginSession, bool) {
	r, ok := activeLoginSessions.Load(loginSession)
	if ok && r != nil && r.(LoginSession).created.Before(time.Now()) {
		return r.(LoginSession), true
	}
	return LoginSession{}, false
}

func createLoginSession(loginSessionKey string, cognitoSession string, nextStep NextStep, expires time.Time, tag interface{}) {
	activeLoginSessions.Store(loginSessionKey,
		LoginSession{cognitoSession,
			time.Now(),
			expires,
			nextStep,
			tag})
}

type initiateResetPasswordSession struct {
	user    string
	email   string
	used    bool
	created time.Time
	expires time.Time
}

func (l initiateResetPasswordSession) GetStartTime() time.Time {
	return l.created
}

func (l initiateResetPasswordSession) GetExpirationTime() time.Time {
	return l.expires
}

var activeInitiateResetPasswordSessions = new(sync.Map)

func getResetPasswordSession(token string) (*initiateResetPasswordSession, bool) {
	r, ok := activeInitiateResetPasswordSessions.Load(token)
	if ok && r != nil && r.(*initiateResetPasswordSession).created.Before(time.Now()) {
		return r.(*initiateResetPasswordSession), true
	}
	return nil, false
}

func createResetPasswordSession(resetPasswordSessionKey string, user string, email string, expires time.Time) {
	activeInitiateResetPasswordSessions.Store(resetPasswordSessionKey, &initiateResetPasswordSession{
		user,
		email,
		false,
		time.Now(),
		expires,
	})
}
