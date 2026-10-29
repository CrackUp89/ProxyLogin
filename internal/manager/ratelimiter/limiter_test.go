package ratelimiter

import (
	"context"
	"os"
	"proxylogin/internal/manager/redisclient"
	"proxylogin/internal/manager/storage"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestFactories(t *testing.T) map[string]*Factory {
	factories := map[string]*Factory{
		"memory": NewFactory(Config{StorageType: storage.MemoryType, IdleTTL: time.Minute}, redisclient.Config{}),
	}

	redisUrl := os.Getenv("REDIS_URL")
	if redisUrl == "" {
		t.Log("REDIS_URL not set, skipping redis limiters")
		return factories
	}

	v := viper.New()
	redisclient.SetDefaultConfig(v)
	v.Set("redis.url", redisUrl)
	redisCfg, err := redisclient.LoadConfig(v)
	require.NoError(t, err)

	factories["redis"] = NewFactory(Config{StorageType: storage.RedisType, IdleTTL: time.Minute}, redisCfg)
	return factories
}

func allowN(t *testing.T, l Limiter, key string, n int) int {
	allowed := 0
	for range n {
		ok, err := l.Allow(context.Background(), key)
		require.NoError(t, err)
		if ok {
			allowed++
		}
	}
	return allowed
}

func TestLimiter(t *testing.T) {
	for name, f := range newTestFactories(t) {
		t.Run(name, func(t *testing.T) {
			t.Run("burst equals limit", func(t *testing.T) {
				l := f.NewLimiter("test-"+uuid.NewString(), 10, time.Minute)
				assert.Equal(t, 10, allowN(t, l, "key", 15))
			})

			t.Run("keys are independent", func(t *testing.T) {
				l := f.NewLimiter("test-"+uuid.NewString(), 1, time.Minute)
				assert.Equal(t, 1, allowN(t, l, "a", 2))
				assert.Equal(t, 1, allowN(t, l, "b", 2))
			})

			t.Run("refills over the window", func(t *testing.T) {
				l := f.NewLimiter("test-"+uuid.NewString(), 2, time.Second)
				assert.Equal(t, 2, allowN(t, l, "key", 3))
				time.Sleep(600 * time.Millisecond)
				assert.Equal(t, 1, allowN(t, l, "key", 2))
			})
		})
	}
}

func TestTotalLimiter(t *testing.T) {
	for name, f := range newTestFactories(t) {
		t.Run(name, func(t *testing.T) {
			t.Run("allows max attempts", func(t *testing.T) {
				l := f.NewTotalLimiter("test-"+uuid.NewString(), 3)
				assert.Equal(t, 3, allowN(t, l, "key", 5))
			})

			t.Run("drop resets the counter", func(t *testing.T) {
				l := f.NewTotalLimiter("test-"+uuid.NewString(), 2)
				assert.Equal(t, 2, allowN(t, l, "key", 3))
				require.NoError(t, l.Drop(context.Background(), "key"))
				assert.Equal(t, 2, allowN(t, l, "key", 3))
			})
		})
	}
}
