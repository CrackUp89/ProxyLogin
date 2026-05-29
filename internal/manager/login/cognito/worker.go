package cognito

import (
	"fmt"
	loginTypes "proxylogin/internal/manager/login/types"

	"go.uber.org/zap"
)

var workersLogger *zap.Logger

func getWorkersLogger() *zap.Logger {
	if workersLogger == nil {
		workersLogger = getLogger().Named("workers")
	}
	return workersLogger
}

func (c *Cognito) startWorker() chan bool {
	stopChannel := make(chan bool)
	go func() {
		for {
			select {
			case t := <-c.tasks:
				c.processTask(t)
			case <-stopChannel:
				return
			}
		}
	}()
	return stopChannel
}

func (c *Cognito) StartWorkers(num uint64) func() {
	stopChannels := make([]chan bool, num)
	for i := uint64(0); i < num; i++ {
		stopChannels[i] = c.startWorker()
	}
	getWorkersLogger().Info("Workers started", zap.Uint64("num", num))
	return func() {
		for _, stopChannel := range stopChannels {
			stopChannel <- true
		}
	}
}

func (c *Cognito) processTask(t taskWrapper) {
	if t.done != nil {
		defer t.done()
	}
	defer func() {
		if p := recover(); p != nil {
			getWorkersLogger().Error("task panicked", zap.Any("panic", p), zap.Stack("stack"))
			t.task.fail(loginTypes.NewInternalError("task panicked", fmt.Errorf("%v", p)))
		}
	}()
	t.task.Process(c)
}
