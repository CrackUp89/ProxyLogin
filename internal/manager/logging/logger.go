package logging

import (
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var logger *zap.Logger

func LoadConfig() {
	devMode := viper.GetBool("logging.dev")
	var err error

	if devMode {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}

	if err != nil {
		panic(err)
	}

	defer logger.Sync()
	logger = logger.WithOptions(zap.AddStacktrace(zap.ErrorLevel))
}

func GetLogger() *zap.Logger {
	return logger
}

func NewLogger(name string) *zap.Logger {
	return logger.Named(name)
}
