package redisclient

import (
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
)

var defaultRedisClientOptions *redis.Options
var defaultKeyPrefix string

func init() {
	viper.SetDefault("redis.url", "redis://localhost:6379/0?protocol=3")
	viper.SetDefault("redis.keyprefix", "proxylogin:")
	viper.SetDefault("redis.clientname", "proxylogin")
	viper.SetDefault("redis.connmaxlifetime", 180)
	viper.SetDefault("redis.maxactiveconns", 500)
	viper.SetDefault("redis.maxidleconns", 500)
}

type ClientWrapper struct {
	client    *redis.Client
	keyPrefix string
}

var client *ClientWrapper

func LoadConfig() {
	var err error
	defaultRedisClientOptions, err = redis.ParseURL(viper.GetString("redis.url"))
	if err != nil {
		panic(err)
	}

	defaultRedisClientOptions.ClientName = viper.GetString("redis.clientname")
	defaultRedisClientOptions.ConnMaxLifetime = viper.GetDuration("redis.connmaxlifetime") * time.Second
	defaultRedisClientOptions.MaxActiveConns = viper.GetInt("redis.maxactiveconns")
	defaultRedisClientOptions.MaxIdleConns = viper.GetInt("redis.maxidleconns")

	defaultKeyPrefix = viper.GetString("redis.keyprefix")
}

var clientOnce = &sync.Once{}

func GetDefaultClient() *ClientWrapper {
	clientOnce.Do(func() {
		client = &ClientWrapper{
			client:    redis.NewClient(defaultRedisClientOptions),
			keyPrefix: defaultKeyPrefix,
		}
	})
	return client
}

func (c *ClientWrapper) BuildKey(parts ...string) string {
	sb := strings.Builder{}
	sb.WriteString(c.keyPrefix)
	for _, part := range parts {
		sb.WriteString(part)
	}
	return sb.String()
}

func (c *ClientWrapper) Client() *redis.Client {
	return c.client
}
