package cognito

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"proxylogin/internal/manager/rds"
	"proxylogin/internal/manager/tools"
	"reflect"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var sessionsLogger *zap.Logger

func getSessionsLogger() *zap.Logger {
	if sessionsLogger == nil {
		sessionsLogger = getLogger().Named("sessions")
	}
	return sessionsLogger
}

type SessionStorage interface {
	GetLoginSession(ctx context.Context, loginSession string) (*LoginSession, error)
	CreateLoginSession(ctx context.Context, loginSessionKey string, cognitoSession string, nextStep NextStep, expires time.Time, tag interface{}) error
	GetResetPasswordSession(ctx context.Context, token string) (*InitiateResetPasswordSession, error)
	CreateResetPasswordSession(ctx context.Context, resetPasswordSessionKey string, user string, email string, expires time.Time) error
	DropResetPasswordSession(ctx context.Context, token string) error
}

var sessionStorage SessionStorage

type storageType string

var (
	MEMORY storageType = "memory"
	REDIS  storageType = "redis"
)

func init() {
	viper.SetDefault("cognito.sessions.storage", MEMORY)
}

func loadSessionSettings() {
	switch storageType(viper.GetString("cognito.sessions.storage")) {
	case MEMORY:
		sessionStorage = NewLocalSessionStore()
		startLocalStorageCleanupRoutine()
		break
	case REDIS:
		sessionStorage = NewRedisSessionStore()
		break
	default:
		panic("invalid storage type")
	}
}

type withValidityTimeframe interface {
	GetStartTime() time.Time
	GetExpirationTime() time.Time
}

func cleanupExpiredSessions[T withValidityTimeframe](sessions *sync.Map) {
	sessions.Range(func(k, v interface{}) bool {
		session := v.(T)
		if session.GetStartTime().After(time.Now()) {
			getSessionsLogger().Info("session expired",
				zap.String("session", k.(string)),
				zap.String("type", fmt.Sprint(reflect.TypeOf(session))))
			sessions.Delete(k)
		}
		return true
	})
}

func startLocalStorageCleanupRoutine() func() {
	stop := make(chan bool, 1)
	go func() {
		cleanup := time.NewTicker(15 * time.Second)
		for {
			select {
			case <-cleanup.C:
				cleanupExpiredSessions[LoginSession](sessionStorage.(*LocalSessionStore).activeLoginSessions)
				cleanupExpiredSessions[*InitiateResetPasswordSession](sessionStorage.(*LocalSessionStore).activeInitiateResetPasswordSessions)
			case <-stop:
				getSessionsLogger().Info("Session cleanup routine stopped")
				return
			}
		}
	}()
	return func() {
		stop <- true
	}
}

var loginSessionMutexManager = tools.NamedMutexManager{}

func lockLoginSession(sessionKey string) func() {
	if sessionKey == "" {
		return func() {
			getSessionsLogger().Warn("can not lock session - session key is empty", zap.Stack("stack"))
		}
	}
	lock := loginSessionMutexManager.GetNamedMutex(sessionKey)
	lock.Lock()
	return func() { lock.Unlock() }
}

type LoginSession struct {
	CognitoSession string      `json:"cognito_session"`
	Created        time.Time   `json:"created"`
	Expires        time.Time   `json:"expires"`
	NextStep       NextStep    `json:"nextStep"`
	Tag            interface{} `json:"tag"`
}

func (l LoginSession) GetStartTime() time.Time {
	return l.Created
}

func (l LoginSession) GetExpirationTime() time.Time {
	return l.Expires
}

type InitiateResetPasswordSession struct {
	User    string    `json:"user"`
	Email   string    `json:"email"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
}

func (l InitiateResetPasswordSession) GetStartTime() time.Time {
	return l.Created
}

func (l InitiateResetPasswordSession) GetExpirationTime() time.Time {
	return l.Expires
}

type LocalSessionStore struct {
	activeLoginSessions                 *sync.Map
	activeInitiateResetPasswordSessions *sync.Map
}

func (l *LocalSessionStore) DropResetPasswordSession(_ context.Context, token string) error {
	l.activeInitiateResetPasswordSessions.Delete(token)
	return nil
}

func NewLocalSessionStore() *LocalSessionStore {
	return &LocalSessionStore{
		activeLoginSessions:                 new(sync.Map),
		activeInitiateResetPasswordSessions: new(sync.Map),
	}
}

func (l *LocalSessionStore) GetLoginSession(_ context.Context, loginSession string) (*LoginSession, error) {
	r, ok := l.activeLoginSessions.Load(loginSession)
	if ok && r != nil && r.(LoginSession).Created.Before(time.Now()) {
		return r.(*LoginSession), nil
	}
	return nil, nil
}

func (l *LocalSessionStore) CreateLoginSession(_ context.Context, loginSessionKey string, cognitoSession string, nextStep NextStep, expires time.Time, tag interface{}) error {
	l.activeLoginSessions.Store(loginSessionKey,
		&LoginSession{cognitoSession,
			time.Now(),
			expires,
			nextStep,
			tag})
	return nil
}

func (l *LocalSessionStore) GetResetPasswordSession(_ context.Context, token string) (*InitiateResetPasswordSession, error) {
	r, ok := l.activeInitiateResetPasswordSessions.Load(token)
	if ok && r != nil && r.(*InitiateResetPasswordSession).Created.Before(time.Now()) {
		return r.(*InitiateResetPasswordSession), nil
	}
	return nil, nil
}

func (l *LocalSessionStore) CreateResetPasswordSession(_ context.Context, resetPasswordSessionKey string, user string, email string, expires time.Time) error {
	l.activeInitiateResetPasswordSessions.Store(resetPasswordSessionKey, &InitiateResetPasswordSession{
		user,
		email,
		time.Now(),
		expires,
	})
	return nil
}

type RedisSessionStore struct {
}

const (
	loginSessionPrefix         = "cognito:loginSession:"
	resetPasswordSessionPrefix = "cognito:resetSession:"
)

func NewRedisSessionStore() *RedisSessionStore {
	return &RedisSessionStore{}
}

func (r *RedisSessionStore) GetLoginSession(ctx context.Context, loginSession string) (*LoginSession, error) {
	key := rds.BuildKey(loginSessionPrefix, loginSession)
	data, err := rds.GetClient().Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		getSessionsLogger().Error("failed to get login session from redis",
			zap.String("session", loginSession),
			zap.Error(err))
		return nil, err
	}

	var session LoginSession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		getSessionsLogger().Error("failed to unmarshal login session",
			zap.String("session", loginSession),
			zap.Error(err))
		return nil, err
	}

	if session.Created.Before(time.Now()) && session.Expires.After(time.Now()) {
		return &session, nil
	}

	return nil, nil
}

func (r *RedisSessionStore) CreateLoginSession(ctx context.Context, loginSessionKey string, cognitoSession string, nextStep NextStep, expires time.Time, tag interface{}) error {
	key := rds.BuildKey(loginSessionPrefix, loginSessionKey)
	session := &LoginSession{
		CognitoSession: cognitoSession,
		Created:        time.Now(),
		Expires:        expires,
		NextStep:       nextStep,
		Tag:            tag,
	}

	data, err := json.Marshal(session)
	if err != nil {
		getSessionsLogger().Error("failed to marshal login session",
			zap.String("session", loginSessionKey),
			zap.Error(err))
		return err
	}

	ttl := time.Until(expires)
	if ttl < 0 {
		ttl = 0
	}

	if err := rds.GetClient().Set(ctx, key, data, ttl).Err(); err != nil {
		getSessionsLogger().Error("failed to create login session in redis",
			zap.String("session", loginSessionKey),
			zap.Error(err))
		return err
	}

	getSessionsLogger().Debug("created login session in redis",
		zap.String("session", loginSessionKey),
		zap.Duration("ttl", ttl))

	return nil
}

func (r *RedisSessionStore) GetResetPasswordSession(ctx context.Context, token string) (*InitiateResetPasswordSession, error) {
	key := rds.BuildKey(resetPasswordSessionPrefix, token)
	data, err := rds.GetClient().Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		getSessionsLogger().Error("failed to get reset password session from redis",
			zap.String("token", token),
			zap.Error(err))
		return nil, err
	}

	var session InitiateResetPasswordSession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		getSessionsLogger().Error("failed to unmarshal reset password session",
			zap.String("token", token),
			zap.Error(err))
		return nil, err
	}

	if session.Created.Before(time.Now()) && session.Expires.After(time.Now()) {
		return &session, nil
	}

	return nil, nil
}

func (r *RedisSessionStore) CreateResetPasswordSession(ctx context.Context, resetPasswordSessionKey string, user string, email string, expires time.Time) error {
	key := rds.BuildKey(resetPasswordSessionPrefix, resetPasswordSessionKey)
	session := &InitiateResetPasswordSession{
		User:    user,
		Email:   email,
		Created: time.Now(),
		Expires: expires,
	}

	data, err := json.Marshal(session)
	if err != nil {
		getSessionsLogger().Error("failed to marshal reset password session",
			zap.String("token", resetPasswordSessionKey),
			zap.Error(err))
		return err
	}

	ttl := time.Until(expires)
	if ttl < 0 {
		ttl = 0
	}

	if err := rds.GetClient().Set(ctx, key, data, ttl).Err(); err != nil {
		getSessionsLogger().Error("failed to create reset password session in redis",
			zap.String("token", resetPasswordSessionKey),
			zap.Error(err))
		return err
	}

	getSessionsLogger().Debug("created reset password session in redis",
		zap.String("token", resetPasswordSessionKey),
		zap.Duration("ttl", ttl))

	return nil
}

func (r *RedisSessionStore) DropResetPasswordSession(ctx context.Context, token string) error {
	key := rds.BuildKey(resetPasswordSessionPrefix, token)
	if err := rds.GetClient().Del(ctx, key).Err(); err != nil {
		getSessionsLogger().Error("failed to delete reset password session from redis",
			zap.String("token", token),
			zap.Error(err))
		return err
	}

	getSessionsLogger().Debug("dropped reset password session from redis",
		zap.String("token", token))

	return nil
}
