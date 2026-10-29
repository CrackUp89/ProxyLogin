package ratelimiter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"proxylogin/internal/manager/redisclient"
	"proxylogin/internal/manager/storage"
	"sync"
	"time"

	"github.com/go-redis/redis_rate/v10"
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
	v.SetDefault("ratelimiter.storage", "")  // empty: same as storage.type
	v.SetDefault("ratelimiter.idleTTL", 300) //todo: make individually configurable
}

func LoadConfig(v *viper.Viper) (Config, error) {
	r := Config{}

	var err error
	storageType := v.GetString("ratelimiter.storage")
	if storageType == "" {
		storageType = v.GetString("storage.type")
	}
	r.StorageType, err = storage.ParseType(storageType)
	if err != nil {
		return r, fmt.Errorf("ratelimiter: %w", err)
	}

	idleTTL := v.GetInt("ratelimiter.idleTTL")
	if idleTTL < 1 {
		return r, fmt.Errorf("ratelimiter: idleTTL must be at least 1")
	}
	r.IdleTTL = time.Duration(idleTTL) * time.Second

	return r, nil
}

// Factory creates limiters backed by the configured storage.
type Factory struct {
	cfg          Config
	client       *redisclient.ClientWrapper
	redisLimiter *redis_rate.Limiter
}

func NewFactory(cfg Config, redisCfg redisclient.Config) *Factory {
	f := &Factory{cfg: cfg}
	if cfg.StorageType == storage.RedisType {
		f.client = redisclient.GetDefaultClient(redisCfg)
		f.redisLimiter = redis_rate.NewLimiter(f.client.Client())
	}
	return f
}

// hashKey hashes a limiter key before it is used in a redis key name; keys may contain tokens or other secrets
func hashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
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

// NewLimiter creates a token bucket limiter allowing limit requests per window: up to limit requests at once,
// refilled evenly over the window. Both storage types implement the same algorithm (GCRA in redis).
func (f *Factory) NewLimiter(name string, limit int, window time.Duration) Limiter {
	switch f.cfg.StorageType {
	case storage.MemoryType:
		return NewTokenBucketLimiter(name, rate.Every(window/time.Duration(limit)), limit, f.cfg.IdleTTL)
	case storage.RedisType:
		return NewRedisRateLimiter(f.client, f.redisLimiter, name, limit, window)
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
	client  *redisclient.ClientWrapper
	limiter *redis_rate.Limiter
	name    string
	limit   redis_rate.Limit
}

func NewRedisRateLimiter(client *redisclient.ClientWrapper, limiter *redis_rate.Limiter, name string, limit int, window time.Duration) *RedisRateLimiter {
	return &RedisRateLimiter{
		client:  client,
		limiter: limiter,
		name:    name,
		limit: redis_rate.Limit{
			Rate:   limit,
			Burst:  limit,
			Period: window,
		},
	}
}

func (rrl *RedisRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	res, err := rrl.limiter.Allow(ctx, rrl.client.BuildKey("ratelimit:", rrl.name, ":", hashKey(key)), rrl.limit)
	if err != nil {
		return false, err
	}
	return res.Allowed > 0, nil
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
		return NewRedisTotalLimiter(f.client, name, max, f.cfg.IdleTTL)
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

// RedisTotalLimiter counts attempts per key. Like the memory implementation, a counter is forgotten after idleTTL
// without attempts.
type RedisTotalLimiter struct {
	client  *redisclient.ClientWrapper
	name    string
	max     int64
	idleTTL time.Duration
}

func NewRedisTotalLimiter(client *redisclient.ClientWrapper, name string, max int64, idleTTL time.Duration) *RedisTotalLimiter {
	return &RedisTotalLimiter{
		client:  client,
		name:    name,
		max:     max,
		idleTTL: idleTTL,
	}
}

func (l *RedisTotalLimiter) redisKey(key string) string {
	return l.client.BuildKey("totallimit:", l.name, ":", hashKey(key))
}

func (l *RedisTotalLimiter) Allow(ctx context.Context, key string) (bool, error) {
	if l.max < 1 {
		return true, nil
	}

	redisKey := l.redisKey(key)

	// MULTI/EXEC so the counter never ends up without a TTL
	pipe := l.client.Client().TxPipeline()
	incr := pipe.Incr(ctx, redisKey)
	pipe.Expire(ctx, redisKey, l.idleTTL)

	if _, err := pipe.Exec(ctx); err != nil {
		return false, err
	}

	return incr.Val() <= l.max, nil
}

func (l *RedisTotalLimiter) Drop(ctx context.Context, key string) error {
	return l.client.Client().Del(ctx, l.redisKey(key)).Err()
}
