package ratelimiter

import (
	"context"
	"proxylogin/internal/manager/redisclient"
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

var idleTTL time.Duration

func init() {
	viper.SetDefault("ratelimiter.storage", MEMORY)
	viper.SetDefault("ratelimiter.idleTTL", 300) //todo: make individually configurable
}

func LoadConfig() {
	limiterStorageType = storageType(viper.GetString("ratelimiter.storage"))
	idleTTL = viper.GetDuration("ratelimiter.idleTTL") * time.Second
}

func startEvictionRoutine(name string, evict func()) {
	go func() {
		ticker := time.NewTicker(idleTTL / 2)
		defer ticker.Stop()
		for range ticker.C {
			evict()
		}
	}()
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

type limiterEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

type TokenBucketLimiter struct {
	name     string
	mu       sync.Mutex
	limiters map[string]*limiterEntry
	rate     rate.Limit
	burst    int
}

func NewTokenBucketLimiter(name string, rps rate.Limit, burst int) *TokenBucketLimiter {
	tbl := &TokenBucketLimiter{
		name:     name,
		limiters: make(map[string]*limiterEntry),
		rate:     rps,
		burst:    burst,
	}
	startEvictionRoutine(name, func() { tbl.evictIdle() })
	return tbl
}

func (tbl *TokenBucketLimiter) getLimiter(key string) *rate.Limiter {
	tbl.mu.Lock()
	defer tbl.mu.Unlock()

	entry, exists := tbl.limiters[key]
	if !exists {
		entry = &limiterEntry{
			limiter:    rate.NewLimiter(tbl.rate, tbl.burst),
			lastAccess: time.Now(),
		}
		tbl.limiters[key] = entry
	} else {
		entry.lastAccess = time.Now()
	}

	return entry.limiter
}

func (tbl *TokenBucketLimiter) evictIdle() {
	tbl.mu.Lock()
	defer tbl.mu.Unlock()

	cutoff := time.Now().Add(-idleTTL)
	for key, entry := range tbl.limiters {
		if entry.lastAccess.Before(cutoff) {
			delete(tbl.limiters, key)
		}
	}
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
	clientWrapper := redisclient.GetDefaultClient()
	client := clientWrapper.Client()
	redisKey := clientWrapper.BuildKey("ratelimit:", rrl.name, ":", key)

	pipe := client.Pipeline()
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

type counterEntry struct {
	count      int64
	lastAccess time.Time
}

type TokenBucketTotalLimiter struct {
	name     string
	mu       sync.Mutex
	counters map[string]*counterEntry
	max      int64
}

func NewTokenBucketTotalLimiter(name string, max int64) *TokenBucketTotalLimiter {
	l := &TokenBucketTotalLimiter{
		name:     name,
		counters: make(map[string]*counterEntry),
		max:      max,
	}
	startEvictionRoutine(name, func() { l.evictIdle() })
	return l
}

func (l *TokenBucketTotalLimiter) Allow(ctx context.Context, key string) (bool, error) {
	if l.max < 1 {
		return true, nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entry, exists := l.counters[key]
	if !exists {
		l.counters[key] = &counterEntry{count: 1, lastAccess: time.Now()}
		return true, nil
	}

	entry.lastAccess = time.Now()

	if entry.count >= l.max {
		return false, nil
	}

	entry.count++
	return true, nil
}

func (l *TokenBucketTotalLimiter) evictIdle() {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := time.Now().Add(-idleTTL)
	for key, entry := range l.counters {
		if entry.lastAccess.Before(cutoff) {
			delete(l.counters, key)
		}
	}
}

func (l *TokenBucketTotalLimiter) Drop(ctx context.Context, key string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
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

	clientWrapper := redisclient.GetDefaultClient()
	client := clientWrapper.Client()

	redisKey := clientWrapper.BuildKey("totallimit:", l.name, ":", key)

	incr := client.Incr(ctx, redisKey)
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
	clientWrapper := redisclient.GetDefaultClient()
	client := clientWrapper.Client()

	redisKey := clientWrapper.BuildKey("totallimit:", l.name, ":", key)
	return client.Del(ctx, redisKey).Err()
}
