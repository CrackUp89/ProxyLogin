package logging

import (
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type Config struct {
	Dev        bool
	Verbose    bool
	InstanceID string
}

var EnvBinds = map[string]string{
	"logging.dev":     "LOGGING_DEV",
	"logging.verbose": "LOGGING_VERBOSE",
	"instance.id":     "INSTANCE_ID",
}

func SetDefaultConfig(v *viper.Viper) {
	v.SetDefault("logging.dev", false)
	v.SetDefault("logging.verbose", false)
	v.SetDefault("instance.id", "proxylogin")
}

func LoadConfig(v *viper.Viper) (Config, error) {
	return Config{
		Dev:        v.GetBool("logging.dev"),
		Verbose:    v.GetBool("logging.verbose"),
		InstanceID: v.GetString("instance.id"),
	}, nil
}

var logger *zap.Logger

// Setup builds the root logger. It must run before any NewLogger call.
func Setup(cfg Config) {
	var err error

	if cfg.Dev {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}

	if err != nil {
		panic(err)
	}

	opts := []zap.Option{
		zap.AddStacktrace(zap.PanicLevel),
	}

	if cfg.Verbose {
		opts = append(opts, zap.IncreaseLevel(zap.DebugLevel))
	}

	defer logger.Sync()
	logger = logger.WithOptions(opts...).With(zap.String("instanceId", cfg.InstanceID))
}

func GetRootLogger() *zap.Logger {
	return logger
}

func NewLogger(name string) *zap.Logger {
	return logger.Named(name)
}
