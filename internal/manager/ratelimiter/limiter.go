package ratelimiter

import (
	"context"
	"fmt"
	"proxylogin/internal/manager/redisclient"
	"proxylogin/internal/manager/storage"
	"sync"
	"time"

	"github.com/spf13/viper"
	"golang.org/x/time/rate"
)

type Config struct {
	StorageType storage.Type
	IdleTTL     time.Duration
}

var EnvBinds = map[string]string{
	"ratelimiter.storage": "RATELIMITER_STORAGE",
	"ratelimiter.idleTTL": "RATELIMITER_IDLE_TTL",
}

func SetDefaultConfig(v *viper.Viper) {
	v.SetDefault("ratelimiter.storage", storage.MemoryType)
	v.SetDefault("ratelimiter.idleTTL", 300) //todo: make individually configurable
}

func LoadConfig(v *viper.Viper) (Config, error) {
	r := Config{}

	var err error
	r.StorageType, err = storage.ParseType(v.GetString("ratelimiter.storage"))
	if err != nil {
		return r, fmt.Errorf("ratelimiter: %w", err)
	}

	r.IdleTTL = v.GetDuration("ratelimiter.idleTTL") * time.Second

	return r, nil
}

// Factory creates limiters backed by the configured storage.
type Factory struct {
	cfg    Config
	client *redisclient.ClientWrapper
}

func NewFactory(cfg Config, redisCfg redisclient.Config) *Factory {
	f := &Factory{cfg: cfg}
	if cfg.StorageType == storage.RedisType {
		f.client = redisclient.GetDefaultClient(redisCfg)
	}
	return f
}

func startEvictionRoutine(idleTTL time.Duration, evict func()) {
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

func (f *Factory) NewLimiter(name string, limit int, window time.Duration) Limiter {
	switch f.cfg.StorageType {
	case storage.MemoryType:
		burst := int(float32(limit) / float32(window/time.Second))
		if burst < 1 {
			burst = 1
		}
		rps := rate.Every(window / time.Duration(limit))
		return NewTokenBucketLimiter(name, rps, burst, f.cfg.IdleTTL)
	case storage.RedisType:
		return NewRedisRateLimiter(f.client, name, limit, window)
	}
	panic("invalid storage type")
}

type noOpLimiter struct{}

var NoOpLimiter = &noOpLimiter{}

func (n noOpLimiter) Allow(_ context.Context, _ string) (bool, error) {
	return true, nil
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
	idleTTL  time.Duration
}

func NewTokenBucketLimiter(name string, rps rate.Limit, burst int, idleTTL time.Duration) *TokenBucketLimiter {
	tbl := &TokenBucketLimiter{
		name:     name,
		limiters: make(map[string]*limiterEntry),
		rate:     rps,
		burst:    burst,
		idleTTL:  idleTTL,
	}
	startEvictionRoutine(idleTTL, func() { tbl.evictIdle() })
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

	cutoff := time.Now().Add(-tbl.idleTTL)
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
	client *redisclient.ClientWrapper
	name   string
	limit  int
	window time.Duration
}

func NewRedisRateLimiter(client *redisclient.ClientWrapper, name string, limit int, window time.Duration) *RedisRateLimiter {
	return &RedisRateLimiter{
		client: client,
		name:   name,
		limit:  limit,
		window: window,
	}
}

func (rrl *RedisRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	client := rrl.client.Client()
	redisKey := rrl.client.BuildKey("ratelimit:", rrl.name, ":", key)

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

func (f *Factory) NewTotalLimiter(name string, max int64) TotalLimiter {
	switch f.cfg.StorageType {
	case storage.MemoryType:
		return NewTokenBucketTotalLimiter(name, max, f.cfg.IdleTTL)
	case storage.RedisType:
		return NewRedisTotalLimiter(f.client, name, max)
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
	idleTTL  time.Duration
}

func NewTokenBucketTotalLimiter(name string, max int64, idleTTL time.Duration) *TokenBucketTotalLimiter {
	l := &TokenBucketTotalLimiter{
		name:     name,
		counters: make(map[string]*counterEntry),
		max:      max,
		idleTTL:  idleTTL,
	}
	startEvictionRoutine(idleTTL, func() { l.evictIdle() })
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

	cutoff := time.Now().Add(-l.idleTTL)
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
	client *redisclient.ClientWrapper
	name   string
	max    int64
}

func NewRedisTotalLimiter(client *redisclient.ClientWrapper, name string, max int64) *RedisTotalLimiter {
	return &RedisTotalLimiter{
		client: client,
		name:   name,
		max:    max,
	}
}

func (l *RedisTotalLimiter) Allow(ctx context.Context, key string) (bool, error) {
	if l.max < 1 {
		return true, nil
	}

	client := l.client.Client()

	redisKey := l.client.BuildKey("totallimit:", l.name, ":", key)

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
	client := l.client.Client()

	redisKey := l.client.BuildKey("totallimit:", l.name, ":", key)
	return client.Del(ctx, redisKey).Err()
}
