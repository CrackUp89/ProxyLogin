package cognito

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"proxylogin/internal/manager/config"
	"proxylogin/internal/manager/redisclient"
	"proxylogin/internal/manager/tools"
	"reflect"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

var sessionsLogger *zap.Logger

func getSessionsLogger() *zap.Logger {
	if sessionsLogger == nil {
		sessionsLogger = getLogger().Named("sessions")
	}
	return sessionsLogger
}

type LoginSession struct {
	CognitoSession  string          `json:"cognito_session"`
	Created         time.Time       `json:"created"`
	Expires         time.Time       `json:"expires"`
	NextStep        NextStep        `json:"nextStep"`
	NextStepVariant NextStepVariant `json:"nextStepVariant"`
	RememberUser    bool            `json:"rememberUser"`
	Tag             interface{}     `json:"tag"`
}

func (l LoginSession) GetStartTime() time.Time {
	return l.Created
}

func (l LoginSession) GetExpirationTime() time.Time {
	return l.Expires
}

type MFAEnforcementSession struct {
	Created              time.Time             `json:"created"`
	Expires              time.Time             `json:"expires"`
	RememberUser         bool                  `json:"rememberUser"`
	AuthenticationResult *AuthenticationResult `json:"authenticationResult"`
}

func (m MFAEnforcementSession) GetStartTime() time.Time {
	return m.Created
}

func (m MFAEnforcementSession) GetExpirationTime() time.Time {
	return m.Expires
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

type ConfirmResetPasswordSession struct {
	User    string    `json:"user"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
}

func (l ConfirmResetPasswordSession) GetStartTime() time.Time {
	return l.Created
}

func (l ConfirmResetPasswordSession) GetExpirationTime() time.Time {
	return l.Expires
}

type SessionStorage interface {
	GetLoginSession(ctx context.Context, sessionKey string) (*LoginSession, error)
	CreateLoginSession(ctx context.Context, sessionKey string, cognitoSession string, nextStep NextStep, nextStepVariant NextStepVariant, rememberUser bool, expires time.Time, tag interface{}) error
	DropLoginSession(ctx context.Context, sessionKey string) error

	GetResetPasswordSession(ctx context.Context, sessionKey string) (*InitiateResetPasswordSession, error)
	CreateResetPasswordSession(ctx context.Context, sessionKey string, user string, email string, expires time.Time) error
	DropResetPasswordSession(ctx context.Context, sessionKey string) error

	GetConfirmPasswordResetSession(ctx context.Context, sessionKey string) (*ConfirmResetPasswordSession, error)
	CreateConfirmPasswordResetSession(ctx context.Context, sessionKey string, user string, expires time.Time) error
	DropConfirmPasswordResetSession(ctx context.Context, token string) error

	GetMFAEnforcementSession(ctx context.Context, sessionKey string) (*MFAEnforcementSession, error)
	CreateMFAEnforcementSession(ctx context.Context, sessionKey string, rememberUser bool, authenticationResult *AuthenticationResult, expires time.Time) error
	DropMFAEnforcementSession(ctx context.Context, sessionKey string) error
}

var sessionStorage SessionStorage

func createSessionsStorage() {
	switch config.GetStorageType() {
	case config.MemoryStorageType:
		sessionStorage = NewLocalSessionStore()
		startLocalStorageCleanupRoutine()
		break
	case config.RedisStorageType:
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
		if session.GetExpirationTime().Before(time.Now()) {
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
				cleanupExpiredSessions[*LoginSession](sessionStorage.(*LocalSessionStore).activeLoginSessions)
				cleanupExpiredSessions[*InitiateResetPasswordSession](sessionStorage.(*LocalSessionStore).activeInitiateResetPasswordSessions)
				cleanupExpiredSessions[*ConfirmResetPasswordSession](sessionStorage.(*LocalSessionStore).activeConfirmResetPasswordSessions)
				cleanupExpiredSessions[*MFAEnforcementSession](sessionStorage.(*LocalSessionStore).activeMFAEnforcementSessions)
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
		getSessionsLogger().Warn("can not lock session - session key is empty", zap.Stack("stack"))
		return func() {
			getSessionsLogger().Warn("can not unlock session - session key is empty", zap.Stack("stack"))
		}
	}
	lock := loginSessionMutexManager.GetNamedMutex(sessionKey)
	lock.Lock()
	return lock.Unlock
}

type LocalSessionStore struct {
	activeLoginSessions                 *sync.Map
	activeInitiateResetPasswordSessions *sync.Map
	activeConfirmResetPasswordSessions  *sync.Map
	activeMFAEnforcementSessions        *sync.Map
}

func (l *LocalSessionStore) GetConfirmPasswordResetSession(_ context.Context, key string) (*ConfirmResetPasswordSession, error) {
	r, ok := l.activeConfirmResetPasswordSessions.Load(key)
	if ok && r != nil {
		s := r.(*ConfirmResetPasswordSession)
		if s.Created.Before(time.Now()) && s.Expires.After(time.Now()) {
			return s, nil
		}
	}
	return nil, nil
}

func (l *LocalSessionStore) CreateConfirmPasswordResetSession(_ context.Context, key string, user string, expires time.Time) error {
	l.activeConfirmResetPasswordSessions.Store(key,
		&ConfirmResetPasswordSession{
			User:    user,
			Created: time.Now(),
			Expires: expires,
		})
	return nil
}

func (l *LocalSessionStore) DropConfirmPasswordResetSession(_ context.Context, token string) error {
	l.activeConfirmResetPasswordSessions.Delete(token)
	return nil
}

func (l *LocalSessionStore) DropResetPasswordSession(_ context.Context, token string) error {
	l.activeInitiateResetPasswordSessions.Delete(token)
	return nil
}

func (l *LocalSessionStore) GetMFAEnforcementSession(_ context.Context, key string) (*MFAEnforcementSession, error) {
	r, ok := l.activeMFAEnforcementSessions.Load(key)
	if ok && r != nil {
		s := r.(*MFAEnforcementSession)
		if s.Created.Before(time.Now()) && s.Expires.After(time.Now()) {
			return s, nil
		}
	}
	return nil, nil
}

func (l *LocalSessionStore) CreateMFAEnforcementSession(_ context.Context, key string, rememberUser bool, authenticationResult *AuthenticationResult, expires time.Time) error {
	l.activeMFAEnforcementSessions.Store(key, &MFAEnforcementSession{
		Created:              time.Now(),
		Expires:              expires,
		RememberUser:         rememberUser,
		AuthenticationResult: authenticationResult,
	})
	return nil
}

func (l *LocalSessionStore) DropMFAEnforcementSession(_ context.Context, key string) error {
	l.activeMFAEnforcementSessions.Delete(key)
	return nil
}

func NewLocalSessionStore() *LocalSessionStore {
	return &LocalSessionStore{
		activeLoginSessions:                 new(sync.Map),
		activeInitiateResetPasswordSessions: new(sync.Map),
		activeConfirmResetPasswordSessions:  new(sync.Map),
		activeMFAEnforcementSessions:        new(sync.Map),
	}
}

func (l *LocalSessionStore) GetLoginSession(_ context.Context, loginSession string) (*LoginSession, error) {
	r, ok := l.activeLoginSessions.Load(loginSession)
	if ok && r != nil {
		s := r.(*LoginSession)
		if s.Created.Before(time.Now()) && s.Expires.After(time.Now()) {
			return s, nil
		}
	}
	return nil, nil
}

func (l *LocalSessionStore) CreateLoginSession(_ context.Context, loginSessionKey string, cognitoSession string, nextStep NextStep, nextStepVariant NextStepVariant, rememberUser bool, expires time.Time, tag interface{}) error {
	l.activeLoginSessions.Store(loginSessionKey,
		&LoginSession{cognitoSession,
			time.Now(),
			expires,
			nextStep,
			nextStepVariant,
			rememberUser,
			tag})
	return nil
}

func (l *LocalSessionStore) DropLoginSession(_ context.Context, loginSessionKey string) error {
	l.activeLoginSessions.Delete(loginSessionKey)
	return nil
}

func (l *LocalSessionStore) GetResetPasswordSession(_ context.Context, token string) (*InitiateResetPasswordSession, error) {
	r, ok := l.activeInitiateResetPasswordSessions.Load(token)
	if ok && r != nil {
		s := r.(*InitiateResetPasswordSession)
		if s.Created.Before(time.Now()) && s.Expires.After(time.Now()) {
			return s, nil
		}
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
	loginSessionPrefix                = "cognito:loginSession:"
	resetPasswordSessionPrefix        = "cognito:resetSession:"
	confirmPasswordResetSessionPrefix = "cognito:confirmResetSession:"
	mfaEnforcementSessionPrefix       = "cognito:mfaEnforcementSession:"
)

func NewRedisSessionStore() *RedisSessionStore {
	return &RedisSessionStore{}
}

//todo: move get\set\drop to generic funcs

func (r *RedisSessionStore) GetConfirmPasswordResetSession(ctx context.Context, sessionKey string) (*ConfirmResetPasswordSession, error) {
	clientWrapper := redisclient.GetDefaultClient()
	client := clientWrapper.Client()

	key := clientWrapper.BuildKey(confirmPasswordResetSessionPrefix, sessionKey)
	data, err := client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		getSessionsLogger().Error("failed to get login session from redis",
			zap.String("session", sessionKey),
			zap.Error(err))
		return nil, err
	}

	var session ConfirmResetPasswordSession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		getSessionsLogger().Error("failed to unmarshal login session",
			zap.String("session", sessionKey),
			zap.Error(err))
		return nil, err
	}

	if session.Created.Before(time.Now()) && session.Expires.After(time.Now()) {
		return &session, nil
	}

	return nil, nil
}

func (r *RedisSessionStore) CreateConfirmPasswordResetSession(ctx context.Context, sessionKey string, user string, expires time.Time) error {
	clientWrapper := redisclient.GetDefaultClient()
	client := clientWrapper.Client()

	key := clientWrapper.BuildKey(confirmPasswordResetSessionPrefix, sessionKey)
	session := &ConfirmResetPasswordSession{
		User:    user,
		Created: time.Now(),
		Expires: expires,
	}

	data, err := json.Marshal(session)
	if err != nil {
		getSessionsLogger().Error("failed to marshal login session",
			zap.String("session", sessionKey),
			zap.Error(err))
		return err
	}

	ttl := time.Until(expires)
	if ttl < 0 {
		ttl = 0
	}

	if err := client.Set(ctx, key, data, ttl).Err(); err != nil {
		getSessionsLogger().Error("failed to create login session in redis",
			zap.String("session", sessionKey),
			zap.Error(err))
		return err
	}

	getSessionsLogger().Debug("created login session in redis",
		zap.String("session", sessionKey),
		zap.Duration("ttl", ttl))

	return nil
}

func (r *RedisSessionStore) DropConfirmPasswordResetSession(ctx context.Context, sessionKey string) error {
	clientWrapper := redisclient.GetDefaultClient()
	client := clientWrapper.Client()

	key := clientWrapper.BuildKey(confirmPasswordResetSessionPrefix, sessionKey)
	return client.Del(ctx, key).Err()
}

func (r *RedisSessionStore) GetMFAEnforcementSession(ctx context.Context, sessionKey string) (*MFAEnforcementSession, error) {
	clientWrapper := redisclient.GetDefaultClient()
	client := clientWrapper.Client()

	key := clientWrapper.BuildKey(mfaEnforcementSessionPrefix, sessionKey)
	data, err := client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		getSessionsLogger().Error("failed to get MFA enforcement session from redis",
			zap.String("session", sessionKey),
			zap.Error(err))
		return nil, err
	}

	var session MFAEnforcementSession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		getSessionsLogger().Error("failed to unmarshal MFA enforcement session",
			zap.String("session", sessionKey),
			zap.Error(err))
		return nil, err
	}

	if session.Created.Before(time.Now()) && session.Expires.After(time.Now()) {
		return &session, nil
	}

	return nil, nil
}

func (r *RedisSessionStore) CreateMFAEnforcementSession(ctx context.Context, sessionKey string, rememberUser bool, authenticationResult *AuthenticationResult, expires time.Time) error {
	clientWrapper := redisclient.GetDefaultClient()
	client := clientWrapper.Client()

	key := clientWrapper.BuildKey(mfaEnforcementSessionPrefix, sessionKey)
	session := &MFAEnforcementSession{
		Created:              time.Now(),
		Expires:              expires,
		RememberUser:         rememberUser,
		AuthenticationResult: authenticationResult,
	}

	data, err := json.Marshal(session)
	if err != nil {
		getSessionsLogger().Error("failed to marshal MFA enforcement session",
			zap.String("session", sessionKey),
			zap.Error(err))
		return err
	}

	ttl := time.Until(expires)
	if ttl < 0 {
		ttl = 0
	}

	if err := client.Set(ctx, key, data, ttl).Err(); err != nil {
		getSessionsLogger().Error("failed to create MFA enforcement session in redis",
			zap.String("session", sessionKey),
			zap.Error(err))
		return err
	}

	getSessionsLogger().Debug("created MFA enforcement session in redis",
		zap.String("session", sessionKey),
		zap.Duration("ttl", ttl))

	return nil
}

func (r *RedisSessionStore) DropMFAEnforcementSession(ctx context.Context, sessionKey string) error {
	clientWrapper := redisclient.GetDefaultClient()
	client := clientWrapper.Client()

	key := clientWrapper.BuildKey(mfaEnforcementSessionPrefix, sessionKey)
	return client.Del(ctx, key).Err()
}

func (r *RedisSessionStore) GetLoginSession(ctx context.Context, loginSession string) (*LoginSession, error) {
	clientWrapper := redisclient.GetDefaultClient()
	client := clientWrapper.Client()

	key := clientWrapper.BuildKey(loginSessionPrefix, loginSession)
	data, err := client.Get(ctx, key).Result()
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

func (r *RedisSessionStore) CreateLoginSession(ctx context.Context, loginSessionKey string, cognitoSession string, nextStep NextStep, nextStepVariant NextStepVariant, rememberUser bool, expires time.Time, tag interface{}) error {
	clientWrapper := redisclient.GetDefaultClient()
	client := clientWrapper.Client()

	key := clientWrapper.BuildKey(loginSessionPrefix, loginSessionKey)
	session := &LoginSession{
		CognitoSession:  cognitoSession,
		Created:         time.Now(),
		Expires:         expires,
		NextStep:        nextStep,
		NextStepVariant: nextStepVariant,
		RememberUser:    rememberUser,
		Tag:             tag,
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

	if err := client.Set(ctx, key, data, ttl).Err(); err != nil {
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

func (r *RedisSessionStore) DropLoginSession(ctx context.Context, loginSessionKey string) error {
	clientWrapper := redisclient.GetDefaultClient()
	client := clientWrapper.Client()

	key := clientWrapper.BuildKey(loginSessionPrefix, loginSessionKey)
	return client.Del(ctx, key).Err()
}

func (r *RedisSessionStore) GetResetPasswordSession(ctx context.Context, token string) (*InitiateResetPasswordSession, error) {
	clientWrapper := redisclient.GetDefaultClient()
	client := clientWrapper.Client()

	key := clientWrapper.BuildKey(resetPasswordSessionPrefix, token)
	data, err := client.Get(ctx, key).Result()
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
	clientWrapper := redisclient.GetDefaultClient()
	client := clientWrapper.Client()

	key := clientWrapper.BuildKey(resetPasswordSessionPrefix, resetPasswordSessionKey)
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

	if err := client.Set(ctx, key, data, ttl).Err(); err != nil {
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
	clientWrapper := redisclient.GetDefaultClient()
	client := clientWrapper.Client()

	key := clientWrapper.BuildKey(resetPasswordSessionPrefix, token)
	if err := client.Del(ctx, key).Err(); err != nil {
		getSessionsLogger().Error("failed to delete reset password session from redis",
			zap.String("token", token),
			zap.Error(err))
		return err
	}

	getSessionsLogger().Debug("dropped reset password session from redis",
		zap.String("token", token))

	return nil
}
