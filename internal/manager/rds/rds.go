package rds

import (
	"strings"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
)

var client *redis.Client
var redisOptions *redis.Options
var defaultKeyPrefix string

func init() {
	viper.SetDefault("redis.url", "redis://localhost:6379/0?protocol=3")
	viper.SetDefault("redis.keyprefix", "proxylogin:")
}

func LoadConfig() {
	var err error
	redisOptions, err = redis.ParseURL(viper.GetString("redis.url"))
	if err != nil {
		panic(err)
	}

	defaultKeyPrefix = viper.GetString("redis.keyprefix")
}

func GetClient() *redis.Client {
	if client == nil {
		client = redis.NewClient(redisOptions)
	}
	return client
}

func BuildKey(parts ...string) string {
	sb := strings.Builder{}
	sb.WriteString(defaultKeyPrefix)
	for _, part := range parts {
		sb.WriteString(part)
	}
	return sb.String()
}
