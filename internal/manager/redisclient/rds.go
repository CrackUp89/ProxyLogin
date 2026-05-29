package redisclient

import (
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
)

type Config struct {
	DefaultRedisClientOptions *redis.Options
	DefaultKeyPrefix          string
}

func SetDefaultConfig(v *viper.Viper) {
	v.SetDefault("redis.url", "redis://localhost:6379/0?protocol=3")
	v.SetDefault("redis.keyPrefix", "proxylogin:")
	v.SetDefault("redis.clientName", "proxylogin")
	v.SetDefault("redis.connectionMaxLifeTime", 180)
	v.SetDefault("redis.maxActiveConnections", 500)
	v.SetDefault("redis.maxIdleConnections", 500)
}

type ClientWrapper struct {
	client    *redis.Client
	keyPrefix string
}

var client *ClientWrapper

var EnvBinds = map[string]string{
	"redis.url":                   "REDIS_URL",
	"redis.keyPrefix":             "REDIS_KEY",
	"redis.clientName":            "REDIS_CLIENT_NAME",
	"redis.connectionMaxLifeTime": "REDIS_CONNECTION_MAX_LIFETIME",
	"redis.maxActiveConnections":  "REDIS_MAX_ACTIVE_CONNECTIONS",
	"redis.maxIdleConnections":    "REDIS_MAX_IDLE_CONNECTIONS",
}

func LoadConfig(v *viper.Viper) (Config, error) {
	r := Config{}

	defaultRedisClientOptions, err := redis.ParseURL(v.GetString("redis.url"))
	if err != nil {
		return r, err
	}

	defaultRedisClientOptions.ClientName = v.GetString("redis.clientName")
	defaultRedisClientOptions.ConnMaxLifetime = v.GetDuration("redis.connectionMaxLifeTime") * time.Second
	defaultRedisClientOptions.MaxActiveConns = v.GetInt("redis.maxActiveConnections")
	defaultRedisClientOptions.MaxIdleConns = v.GetInt("redis.maxIdleConnections")

	r.DefaultRedisClientOptions = defaultRedisClientOptions

	r.DefaultKeyPrefix = v.GetString("redis.keyPrefix")

	return r, nil
}

var clientOnce = &sync.Once{}

func GetDefaultClient(cfg Config) *ClientWrapper {
	clientOnce.Do(func() {
		client = &ClientWrapper{
			client:    redis.NewClient(cfg.DefaultRedisClientOptions),
			keyPrefix: cfg.DefaultKeyPrefix,
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
