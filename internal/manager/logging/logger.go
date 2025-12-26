package logging

import (
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var logger *zap.Logger

func init() {
	viper.SetDefault("logging.dev", false)
	viper.SetDefault("logging.verbose", false)
}

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

	opts := []zap.Option{
		zap.AddStacktrace(zap.ErrorLevel),
	}

	if viper.GetBool("logging.verbose") {
		opts = append(opts, zap.IncreaseLevel(zap.DebugLevel))
	}

	defer logger.Sync()
	logger = logger.WithOptions(opts...).With(zap.String("instanceId", "instance.id"))
}

func GetRootLogger() *zap.Logger {
	return logger
}

func NewLogger(name string) *zap.Logger {
	return logger.Named(name)
}
