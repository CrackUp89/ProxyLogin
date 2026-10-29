package locking

import (
	"context"
	"os"
	"proxylogin/internal/manager/redisclient"
	"proxylogin/internal/manager/storage"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestProviders(t *testing.T) map[string]*Provider {
	providers := map[string]*Provider{
		"memory": NewProvider(storage.MemoryType, redisclient.Config{}),
	}

	redisUrl := os.Getenv("REDIS_URL")
	if redisUrl == "" {
		t.Log("REDIS_URL not set, skipping redis locks")
		return providers
	}

	v := viper.New()
	redisclient.SetDefaultConfig(v)
	v.Set("redis.url", redisUrl)
	redisCfg, err := redisclient.LoadConfig(v)
	require.NoError(t, err)

	providers["redis"] = NewProvider(storage.RedisType, redisCfg)
	return providers
}

func TestProvider_Lock(t *testing.T) {
	for name, p := range newTestProviders(t) {
		t.Run(name, func(t *testing.T) {
			t.Run("mutual exclusion", func(t *testing.T) {
				key := uuid.NewString()
				var inside, maxInside atomic.Int32
				var wg sync.WaitGroup
				for range 10 {
					wg.Go(func() {
						unlock, err := p.Lock(context.Background(), key, 10*time.Second)
						require.NoError(t, err)
						n := inside.Add(1)
						if n > maxInside.Load() {
							maxInside.Store(n)
						}
						time.Sleep(5 * time.Millisecond)
						inside.Add(-1)
						unlock()
						unlock()
					})
				}
				wg.Wait()
				assert.Equal(t, int32(1), maxInside.Load())
			})

			t.Run("waiting respects context", func(t *testing.T) {
				key := uuid.NewString()
				unlock, err := p.Lock(context.Background(), key, 10*time.Second)
				require.NoError(t, err)
				defer unlock()

				if name == "memory" {
					return // local locks wait without a context, like sync.Mutex
				}
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
				_, err = p.Lock(ctx, key, 10*time.Second)
				assert.ErrorIs(t, err, context.DeadlineExceeded)
			})

			t.Run("expired lock is not released by its previous holder", func(t *testing.T) {
				if name == "memory" {
					return
				}
				key := uuid.NewString()
				unlockA, err := p.Lock(context.Background(), key, 50*time.Millisecond)
				require.NoError(t, err)
				time.Sleep(100 * time.Millisecond)

				unlockB, err := p.Lock(context.Background(), key, 10*time.Second)
				require.NoError(t, err)
				defer unlockB()
				unlockA()

				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
				_, err = p.Lock(ctx, key, 10*time.Second)
				assert.ErrorIs(t, err, context.DeadlineExceeded)
			})
		})
	}
}

func TestLocalLocks_cleanup(t *testing.T) {
	l := &localLocks{}
	unlock := l.lock("a")
	unlock()
	assert.Empty(t, l.locks)
}
