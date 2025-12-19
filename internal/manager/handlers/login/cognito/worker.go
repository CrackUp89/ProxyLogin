package cognito

import (
	"proxylogin/internal/manager/tools"

	"go.uber.org/zap"
)

var workersLogger = tools.NewLogger("Cognito.Workers")

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
			case t := <-mfaVerifyTasks:
				processMFAVerifyTask(t)
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
			case t := <-getMFAStatusTasks:
				processGetMFAStatusTask(t)
				break
			case t := <-updateMFATasks:
				processUpdateMFATask(t)
				break
			case t := <-verifyMFAUpdateTasks:
				processVerifyUpdateMFATask(t)
				break
			case t := <-selectMFATasks:
				processSelectMFATask(t)
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
