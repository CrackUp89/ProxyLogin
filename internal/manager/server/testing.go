package server

import (
	"errors"
	"log"
	"os"
	"proxylogin/internal/manager/config"
	"proxylogin/internal/manager/login/masquerade"
	"proxylogin/internal/manager/ratelimiter"
	"proxylogin/internal/manager/rds"
	"strings"
	"sync"

	"github.com/spf13/viper"
)

var loadConfigOnce = &sync.Once{}

func loadEnvFile() {
	var err error

	v := viper.New()

	v.AddConfigPath(".")
	v.SetConfigName(".env")
	v.SetConfigType("env")

	if err = v.ReadInConfig(); err != nil {
		var nf viper.ConfigFileNotFoundError
		if !errors.As(err, &nf) {
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
	config.LoadConfig()
	rds.LoadConfig()
	ratelimiter.LoadConfig()
	masquerade.LoadConfig()
}

func PrepareTestingEnv() {
	loadConfigOnce.Do(loadConfig)
}
