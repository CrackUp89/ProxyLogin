package locking

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"proxylogin/internal/manager/logging"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	lockRetryMinDelay = 10 * time.Millisecond
	lockRetryMaxDelay = 200 * time.Millisecond
	unlockTimeout     = 5 * time.Second
)

// releaseLockScript deletes the lock only while it is still held by the caller, so a lock that expired and was
// acquired by someone else is never released by the previous holder
var releaseLockScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
	return redis.call("DEL", KEYS[1])
end
return 0
`)

// Lock acquires an exclusive lock on key, waiting until it is free or ctx is done. With redis storage the lock is
// shared by all instances and expires after ttl if the holder never releases it. The returned unlock func is safe to
// call more than once.
func (p *Provider) Lock(ctx context.Context, key string, ttl time.Duration) (func(), error) {
	if p.client == nil {
		return p.localLocks.lock(key), nil
	}
	return p.redisLock(ctx, key, ttl)
}

func (p *Provider) redisLock(ctx context.Context, key string, ttl time.Duration) (func(), error) {
	client := p.client.Client()
	// keys may be session ids, which are secrets, so they are hashed before being used in a key name
	h := sha256.Sum256([]byte(key))
	redisKey := p.client.BuildKey("lock:", hex.EncodeToString(h[:]))
	owner := uuid.NewString()

	delay := lockRetryMinDelay
	for {
		acquired, err := client.SetNX(ctx, redisKey, owner, ttl).Result()
		if err != nil {
			return nil, err
		}
		if acquired {
			break
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		delay = min(delay*2, lockRetryMaxDelay)
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), unlockTimeout)
			defer cancel()
			if err := releaseLockScript.Run(ctx, client, []string{redisKey}, owner).Err(); err != nil && !errors.Is(err, redis.Nil) {
				if l := logging.GetRootLogger(); l != nil {
					l.Named("locking").Warn("failed to release lock", zap.Error(err))
				}
			}
		})
	}, nil
}

// localLocks is a set of named mutexes; an entry is removed once nobody holds or waits for it
type localLocks struct {
	mu    sync.Mutex
	locks map[string]*localLock
}

type localLock struct {
	mu   sync.Mutex
	refs int
}

func (l *localLocks) lock(key string) func() {
	l.mu.Lock()
	if l.locks == nil {
		l.locks = make(map[string]*localLock)
	}
	entry, ok := l.locks[key]
	if !ok {
		entry = &localLock{}
		l.locks[key] = entry
	}
	entry.refs++
	l.mu.Unlock()

	entry.mu.Lock()

	var once sync.Once
	return func() {
		once.Do(func() {
			entry.mu.Unlock()

			l.mu.Lock()
			entry.refs--
			if entry.refs == 0 {
				delete(l.locks, key)
			}
			l.mu.Unlock()
		})
	}
}
