package masquerade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"proxylogin/internal/manager/login/types"
	"proxylogin/internal/manager/redisclient"
	"proxylogin/internal/manager/storage"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func newStorage(storageType storage.Type, redisCfg redisclient.Config) (Storage, error) {
	switch storageType {
	case storage.MemoryType:
		s := newLocalStorage()
		s.startCleanupRoutine()
		return s, nil
	case storage.RedisType:
		return newRedisStorage(redisclient.GetDefaultClient(redisCfg)), nil
	default:
		return nil, fmt.Errorf("masquerade: invalid storage type: %q", storageType)
	}
}

func cleanupExpiredTokens(tokens *sync.Map) {
	tokens.Range(func(k, v interface{}) bool {
		session := v.(*localTokenRecord)
		if !session.expires.IsZero() && session.expires.Before(time.Now()) {
			getMasqueradeLogger().Info("token mask expired",
				zap.String("session", k.(string)))
			tokens.Delete(k)
		}
		return true
	})
}

func (l *LocalMasqueradeStorage) startCleanupRoutine() func() {
	stop := make(chan bool, 1)
	go func() {
		cleanup := time.NewTicker(15 * time.Second)
		for {
			select {
			case <-cleanup.C:
				cleanupExpiredTokens(l.tokens)
			case <-stop:
				getMasqueradeLogger().Info("Token masquerade cleanup routine stopped")
				return
			}
		}
	}()
	return func() {
		stop <- true
	}
}

type TokenRecord struct {
	Value   string    `json:"value"`
	Expires time.Time `json:"expires,omitempty"`
}

type TokenSet = map[types.TokenType]TokenRecord

type MasqueradedRecord struct {
	Tokens TokenSet `json:"tokens"`
	User   string   `json:"user"`
}

type Storage interface {
	HasMasqueradedRecord(ctx context.Context, key string) (bool, error)
	StoreMasqueradedRecord(ctx context.Context, key string, masqueradedRecord *MasqueradedRecord, expires time.Time) error
	GetMasqueradedRecord(ctx context.Context, key string) (*MasqueradedRecord, error)
	DropMasqueradedRecord(ctx context.Context, key string) error
}

type localTokenRecord struct {
	masqueradedRecord *MasqueradedRecord
	expires           time.Time
}
type LocalMasqueradeStorage struct {
	tokens *sync.Map
}

func (l *LocalMasqueradeStorage) HasMasqueradedRecord(_ context.Context, key string) (bool, error) {
	_, ok := l.tokens.Load(key)
	return ok, nil
}

func (l *LocalMasqueradeStorage) StoreMasqueradedRecord(_ context.Context, key string, masqueradedRecord *MasqueradedRecord, expires time.Time) error {
	l.tokens.Store(key, &localTokenRecord{
		masqueradedRecord: masqueradedRecord,
		expires:           expires,
	})
	return nil
}

func (l *LocalMasqueradeStorage) GetMasqueradedRecord(_ context.Context, key string) (*MasqueradedRecord, error) {
	if v, ok := l.tokens.Load(key); ok {
		return v.(*localTokenRecord).masqueradedRecord, nil
	}
	return nil, nil
}

func (l *LocalMasqueradeStorage) DropMasqueradedRecord(_ context.Context, key string) error {
	l.tokens.Delete(key)
	return nil
}

func newLocalStorage() *LocalMasqueradeStorage {
	return &LocalMasqueradeStorage{tokens: new(sync.Map)}
}

type RedisMasqueradeStorage struct {
	client *redisclient.ClientWrapper
}

func (r RedisMasqueradeStorage) buildKey(key string) string {
	return r.client.BuildKey("tokenMasquerade:keys:", key)
}

func (r RedisMasqueradeStorage) HasMasqueradedRecord(ctx context.Context, key string) (bool, error) {
	client := r.client.Client()

	if c, err := client.Exists(ctx, r.buildKey(key)).Result(); err != nil {
		getMasqueradeLogger().Error("failed search for token", zap.Error(err))
		return false, err
	} else {
		return c == 1, nil
	}
}

func (r RedisMasqueradeStorage) StoreMasqueradedRecord(ctx context.Context, key string, masqueradedRecord *MasqueradedRecord, expires time.Time) error {
	data, err := json.Marshal(masqueradedRecord)
	if err != nil {
		return err
	}
	var ttl time.Duration
	if expires.IsZero() {
		ttl = time.Duration(0)
	} else {
		ttl = time.Until(expires)
	}

	client := r.client.Client()

	if err = client.Set(ctx, r.buildKey(key), data, ttl).Err(); err != nil {
		getMasqueradeLogger().Error("failed to store token", zap.Error(err))
		return err
	}

	getMasqueradeLogger().Debug("created a token in redis",
		zap.String("key", key),
		zap.Duration("ttl", ttl))

	return nil
}

func (r RedisMasqueradeStorage) GetMasqueradedRecord(ctx context.Context, key string) (*MasqueradedRecord, error) {
	client := r.client.Client()

	data, err := client.Get(ctx, r.buildKey(key)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		getMasqueradeLogger().Error("failed to token from redis",
			zap.String("key", key),
			zap.Error(err))
		return nil, err
	}

	var masqueradedRecord *MasqueradedRecord
	err = json.Unmarshal([]byte(data), &masqueradedRecord)
	if err != nil {
		return nil, err
	}

	return masqueradedRecord, nil
}

func (r RedisMasqueradeStorage) DropMasqueradedRecord(ctx context.Context, key string) error {
	client := r.client.Client()

	if err := client.Del(ctx, r.buildKey(key)).Err(); err != nil {
		getMasqueradeLogger().Error("failed to delete token from redis",
			zap.String("key", key),
			zap.Error(err))
		return err
	}

	getMasqueradeLogger().Debug("dropped token from redis",
		zap.String("key", key))

	return nil
}

func newRedisStorage(client *redisclient.ClientWrapper) Storage {
	return &RedisMasqueradeStorage{client: client}
}
