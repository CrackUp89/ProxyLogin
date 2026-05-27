package redisclient

import (
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
)

var client *redis.Client
var redisOptions *redis.Options
var defaultKeyPrefix string

func init() {
	viper.SetDefault("redis.url", "redis://localhost:6379/0?protocol=3")
	viper.SetDefault("redis.keyprefix", "proxylogin:")
	viper.SetDefault("redis.clientname", "proxylogin")
	viper.SetDefault("redis.connmaxlifetime", 180)
	viper.SetDefault("redis.maxactiveconns", 500)
	viper.SetDefault("redis.maxidleconns", 500)
}

func LoadConfig() {
	var err error
	redisOptions, err = redis.ParseURL(viper.GetString("redis.url"))
	if err != nil {
		panic(err)
	}

	redisOptions.ClientName = viper.GetString("redis.clientname")
	redisOptions.ConnMaxLifetime = viper.GetDuration("redis.connmaxlifetime") * time.Second
	redisOptions.MaxActiveConns = viper.GetInt("redis.maxactiveconns")
	redisOptions.MaxIdleConns = viper.GetInt("redis.maxidleconns")

	defaultKeyPrefix = viper.GetString("redis.keyprefix")
}

var clientOnce = &sync.Once{}

func GetClient() *redis.Client {
	clientOnce.Do(func() {
		client = redis.NewClient(redisOptions)
	})
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
