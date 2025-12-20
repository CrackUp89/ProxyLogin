package config

import (
	"github.com/spf13/viper"
)

var urlBase string

func LoadConfig() {
	urlBase = viper.GetString("http.urlBase")
	if urlBase == "" {
		host := viper.GetString("http.host")
		if host == "" {
			host = "localhost"
		}
		port := viper.GetString("http.port")
		if port != "" {
			port = ":" + port
		}
		urlBase = "http://" + host + port
	}
}

func GetURLBase() string {
	return urlBase
}
