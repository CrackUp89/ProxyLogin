package tools

import (
	"github.com/spf13/viper"
)

func init() {
	viper.SetDefault("logging.dev", false)
}

//func NewLogger(name string) *zap.Logger {
//	devMode := viper.GetBool("logging.dev")
//	var logger *zap.Logger
//	var err error
//
//	if devMode {
//		logger, err = zap.NewDevelopment()
//	} else {
//		logger, err = zap.NewProduction()
//	}
//
//	if err != nil {
//		panic(err)
//	}
//
//	defer logger.Sync()
//	return logger.Named(name).WithOptions(zap.AddStacktrace(zap.ErrorLevel))
//}
