package server

import (
	"errors"
	"log"
	"os"
	"proxylogin/internal/manager/config"
	"strings"
	"sync"

	"github.com/spf13/viper"
)

var loadConfigOnce = &sync.Once{}
var testingConfig config.Config
var testingConfigErr error

func loadEnvFile() {
	var err error

	v := viper.New()

	v.AddConfigPath(".")
	v.SetConfigName(".env")
	v.SetConfigType("env")

	if err = v.ReadInConfig(); err != nil {
		if _, ok := errors.AsType[viper.ConfigFileNotFoundError](err); !ok {
			log.Fatal(err)
		}
	}

	for _, key := range v.AllKeys() {
		if err = os.Setenv(strings.ToUpper(key), v.GetString(key)); err != nil {
			log.Fatal(err)
		}
	}
}

func loadConfig() {
	loadEnvFile()
	testingConfig, testingConfigErr = config.LoadConfig(viper.New())
}

func PrepareTestingEnv() (config.Config, error) {
	loadConfigOnce.Do(loadConfig)
	return testingConfig, testingConfigErr
}
