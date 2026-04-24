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
		burst := int(float32(limit) / float32(window/time.Second))
		if burst < 1 {
			burst = 1
		}
		rps := rate.Every(window / time.Duration(limit))
		return NewTokenBucketLimiter(name, rps, burst)
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

type TotalLimiter interface {
	Allow(ctx context.Context, key string) (bool, error)
	Drop(ctx context.Context, key string) error
}

func NewTotalLimiter(name string, max int64) TotalLimiter {
	switch limiterStorageType {
	case MEMORY:
		return NewTokenBucketTotalLimiter(name, max)
	case REDIS:
		return NewRedisTotalLimiter(name, max)
	}
	panic("invalid storage type")
}

type TokenBucketTotalLimiter struct {
	name     string
	mu       sync.Mutex
	counters map[string]int64
	max      int64
}

func NewTokenBucketTotalLimiter(name string, max int64) *TokenBucketTotalLimiter {
	return &TokenBucketTotalLimiter{
		name:     name,
		counters: make(map[string]int64),
		max:      max,
	}
}

func (l *TokenBucketTotalLimiter) Allow(ctx context.Context, key string) (bool, error) {
	if l.max < 1 {
		return true, nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	total, exists := l.counters[key]
	if !exists {
		l.counters[key] = 1
		return true, nil
	}

	if total >= l.max {
		return false, nil
	}

	l.counters[key] += 1
	return true, nil
}

func (l *TokenBucketTotalLimiter) Drop(ctx context.Context, key string) error {
	delete(l.counters, key)
	return nil
}

type RedisTotalLimiter struct {
	name string
	max  int64
}

func NewRedisTotalLimiter(name string, max int64) *RedisTotalLimiter {
	return &RedisTotalLimiter{
		name: name,
		max:  max,
	}
}

func (l *RedisTotalLimiter) Allow(ctx context.Context, key string) (bool, error) {
	if l.max < 1 {
		return true, nil
	}

	redisKey := rds.BuildKey("totallimit:", l.name, ":", key)

	incr := rds.GetClient().Incr(ctx, redisKey)
	if err := incr.Err(); err != nil {
		return false, err
	}

	val := incr.Val()
	return val < l.max, nil

	//pipe := rds.GetClient().Pipeline()
	//pipe.Expire(ctx, redisKey, time.Hour)
	//incr := pipe.Incr(ctx, redisKey)
	//
	//_, err := pipe.Exec(ctx)
	//if err != nil {
	//	return false, err
	//}
	//
	//return incr.Val() <= l.max, nil
}

func (l *RedisTotalLimiter) Drop(ctx context.Context, key string) error {
	redisKey := rds.BuildKey("totallimit:", l.name, ":", key)
	return rds.GetClient().Del(ctx, redisKey).Err()
}
