package cognito

import (
	"proxylogin/internal/manager/tools"
	"sync"
	"time"

	"go.uber.org/zap"
)

var sessionsLogger = tools.NewLogger("Cognito.Sessions")

type NextStep string

const (
	NextStepNone                        NextStep = ""
	NextStepMFASetup                    NextStep = "mfa_setup"
	NextStepMFASoftwareTokenSetupVerify NextStep = "mfa_software_token_setup_verify"
	NextStepMFASoftwareTokenVerify      NextStep = "mfa_software_token_verify"
	NextStepNewPassword                 NextStep = "new_password"
)

type LoginSession struct {
	cognitoSession string
	createdAt      time.Time
	nextStep       NextStep
	tag            interface{}
}

var activeSessions = new(sync.Map)
var sessionValidFor = 180.0

func init() {
	go func() {
		cleanup := time.NewTicker(15 * time.Second)
		for {
			select {
			case <-cleanup.C:
				activeSessions.Range(func(k, v interface{}) bool {
					session := v.(LoginSession)
					if time.Since(session.createdAt).Seconds() >= sessionValidFor {
						sessionsLogger.Info("SessionKey expired",
							zap.String("loginSession", k.(string)),
							zap.String("cognitoSession", session.cognitoSession))
						activeSessions.Delete(k)
					}
					return true
				})
			}
		}
	}()
}

func GetSession(loginSession string) (LoginSession, bool) {
	r, ok := activeSessions.Load(loginSession)
	if ok && r != nil {
		return r.(LoginSession), true
	}
	return LoginSession{}, false
}

func SetSession(loginSession string, cognitoSession string, nextStep NextStep, createdAt time.Time, tag interface{}) {
	activeSessions.Store(loginSession, LoginSession{cognitoSession, createdAt, nextStep, tag})
}
