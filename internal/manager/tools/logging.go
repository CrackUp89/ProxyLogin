package tools

import (
	"go.uber.org/zap"
)

func NewLogger(name string) *zap.Logger {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()
	return logger.Named(name).WithOptions(zap.AddStacktrace(zap.ErrorLevel))
}
