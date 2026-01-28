package ratelimiter

import (
	"context"
	"proxylogin/internal/manager/rds"
	"sync"
	"time"

	"github.com/spf13/viper"
	"golang.org/x/time/rate"
)

type storageType string

var (
	MEMORY storageType = "memory"
	REDIS  storageType = "redis"
)

var limiterStorageType storageType

func init() {
	viper.SetDefault("ratelimiter.storage", MEMORY)
}

func LoadConfig() {
	limiterStorageType = storageType(viper.GetString("ratelimiter.storage"))
}

type Limiter interface {
	Allow(ctx context.Context, key string) (bool, error)
}

func NewLimiter(name string, limit int, window time.Duration) Limiter {
	switch limiterStorageType {
	case MEMORY:
		rps := rate.Every(window / time.Duration(limit))
		return NewTokenBucketLimiter(name, rps, 1)
	case REDIS:
		return NewRedisRateLimiter(name, limit, window)
	}
	panic("invalid storage type")
}

type TokenBucketLimiter struct {
	name     string
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	rate     rate.Limit
	burst    int
}

func NewTokenBucketLimiter(name string, rps rate.Limit, burst int) *TokenBucketLimiter {
	return &TokenBucketLimiter{
		name:     name,
		limiters: make(map[string]*rate.Limiter),
		rate:     rps,
		burst:    burst,
	}
}

func (tbl *TokenBucketLimiter) getLimiter(key string) *rate.Limiter {
	tbl.mu.Lock()
	defer tbl.mu.Unlock()

	limiter, exists := tbl.limiters[key]
	if !exists {
		limiter = rate.NewLimiter(tbl.rate, tbl.burst)
		tbl.limiters[key] = limiter
	}

	return limiter
}

func (tbl *TokenBucketLimiter) Allow(ctx context.Context, key string) (bool, error) {
	limiter := tbl.getLimiter(key)
	return limiter.Allow(), nil
}

type KeySource interface {
	Key() string
}

type RedisRateLimiter struct {
	name   string
	limit  int
	window time.Duration
}

func NewRedisRateLimiter(name string, limit int, window time.Duration) *RedisRateLimiter {
	return &RedisRateLimiter{
		name:   name,
		limit:  limit,
		window: window,
	}
}

func (rrl *RedisRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	redisKey := rds.BuildKey("ratelimit:", rrl.name, ":", key)

	pipe := rds.GetClient().Pipeline()
	incr := pipe.Incr(ctx, redisKey)
	pipe.Expire(ctx, redisKey, rrl.window)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, err
	}

	return incr.Val() <= int64(rrl.limit), nil
}
