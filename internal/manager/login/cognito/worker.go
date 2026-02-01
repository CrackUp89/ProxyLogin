package cognito

import (
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func init() {
	viper.SetDefault("cognito.workers", 1000)
}

var workersLogger *zap.Logger

func getWorkersLogger() *zap.Logger {
	if workersLogger == nil {
		workersLogger = getLogger().Named("workers")
	}
	return workersLogger
}

func startWorker() chan bool {
	stopChannel := make(chan bool)
	go func() {
		for {
			select {
			case t := <-tasks:
				t.task.Process()
				if t.done != nil {
					t.done()
				}
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
	getWorkersLogger().Info("Workers started", zap.Uint64("num", num))
	return func() {
		for _, stopChannel := range stopChannels {
			stopChannel <- true
		}
	}
}
