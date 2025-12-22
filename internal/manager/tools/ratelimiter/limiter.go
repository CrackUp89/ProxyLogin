package ratelimiter

import (
	"net/http"
	"sync"

	"golang.org/x/time/rate"
)

type Limiter interface {
	Allow(key string) bool
}

func NewLimiter(rps rate.Limit, burst int) Limiter {
	return NewTokenBucketLimiter(rps, burst)
}

type TokenBucketLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	rate     rate.Limit
	burst    int
}

func NewTokenBucketLimiter(rps rate.Limit, burst int) *TokenBucketLimiter {
	return &TokenBucketLimiter{
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

func (tbl *TokenBucketLimiter) Allow(key string) bool {
	limiter := tbl.getLimiter(key)
	return limiter.Allow()
}

type KeySource interface {
	Key() string
}

func (tbl *TokenBucketLimiter) Middleware(next http.HandlerFunc, source KeySource) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !tbl.Allow(source.Key()) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}
