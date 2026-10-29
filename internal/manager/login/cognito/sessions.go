package cognito

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	loginTypes "proxylogin/internal/manager/login/types"
	"proxylogin/internal/manager/redisclient"
	"proxylogin/internal/manager/storage"
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
	CSRFToken       string          `json:"csrf_token"`
	Created         time.Time       `json:"created"`
	Expires         time.Time       `json:"expires"`
	NextStep        NextStep        `json:"nextStep"`
	NextStepVariant NextStepVariant `json:"nextStepVariant"`
	RememberUser    bool            `json:"rememberUser"`
	Tag             any             `json:"tag"`
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
	User                 string                `json:"user,omitempty"`
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
	GetLoginSession(ctx context.Context, id string) (*LoginSession, error)
	CreateLoginSession(ctx context.Context, csrfToken, id, cognitoSession string, nextStep NextStep, nextStepVariant NextStepVariant, rememberUser bool, expires time.Time, tag any) error
	DropLoginSession(ctx context.Context, id string) error
	HasLoginSession(ctx context.Context, id string) (bool, error)

	GetResetPasswordSession(ctx context.Context, id string) (*InitiateResetPasswordSession, error)
	CreateResetPasswordSession(ctx context.Context, id string, user string, email string, expires time.Time) error
	DropResetPasswordSession(ctx context.Context, id string) error

	GetConfirmPasswordResetSession(ctx context.Context, id string) (*ConfirmResetPasswordSession, error)
	CreateConfirmPasswordResetSession(ctx context.Context, id string, user string, expires time.Time) error
	DropConfirmPasswordResetSession(ctx context.Context, id string) error

	GetMFAEnforcementSession(ctx context.Context, id string) (*MFAEnforcementSession, error)
	CreateMFAEnforcementSession(ctx context.Context, id string, user string, rememberUser bool, authenticationResult *AuthenticationResult, expires time.Time) error
	DropMFAEnforcementSession(ctx context.Context, id string) error

	HasUpdateSession(ctx context.Context, id string) (bool, error)
	GetUpdateSession(ctx context.Context, id string) (*UpdateSession, error)
	CreateUpdateSession(ctx context.Context, id string, session *UpdateSession) error
	DropUpdateSession(ctx context.Context, id string) error
}

func (c *Cognito) createSessionsStorage(storageType storage.Type, redisCfg redisclient.Config) error {
	switch storageType {
	case storage.MemoryType:
		c.sessionStorage = NewLocalSessionStore()
		c.startLocalStorageCleanupRoutine()
	case storage.RedisType:
		c.sessionStorage = NewRedisSessionStore(redisclient.GetDefaultClient(redisCfg))
	default:
		return fmt.Errorf("sessions: invalid storage type: %q", storageType)
	}
	return nil
}

type withValidityTimeframe interface {
	GetStartTime() time.Time
	GetExpirationTime() time.Time
}

func cleanupExpiredSessions[T withValidityTimeframe](sessions *sync.Map) {
	sessions.Range(func(k, v any) bool {
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

func (c *Cognito) startLocalStorageCleanupRoutine() func() {
	stop := make(chan bool, 1)
	go func() {
		cleanup := time.NewTicker(15 * time.Second)
		for {
			select {
			case <-cleanup.C:
				cleanupExpiredSessions[*LoginSession](c.sessionStorage.(*LocalSessionStore).activeLoginSessions)
				cleanupExpiredSessions[*InitiateResetPasswordSession](c.sessionStorage.(*LocalSessionStore).activeInitiateResetPasswordSessions)
				cleanupExpiredSessions[*ConfirmResetPasswordSession](c.sessionStorage.(*LocalSessionStore).activeConfirmResetPasswordSessions)
				cleanupExpiredSessions[*MFAEnforcementSession](c.sessionStorage.(*LocalSessionStore).activeMFAEnforcementSessions)
				cleanupExpiredSessions[*UpdateSession](c.sessionStorage.(*LocalSessionStore).activeUpdateSessions)
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

// sessionLockTTL bounds how long a session stays locked if its holder dies (redis storage only); tasks run with a 60s timeout
const sessionLockTTL = 60 * time.Second

// lockSession locks a login or update session by id, across all instances when storage is redis.
// Session ids are random, so both kinds share one lock space. The returned unlock func is safe to call more than once.
func (c *Cognito) lockSession(ctx context.Context, id string) (func(), loginTypes.GenericError) {
	if id == "" {
		getSessionsLogger().Warn("can not lock session - session key is empty", zap.Stack("stack"))
		return func() {
			getSessionsLogger().Warn("can not unlock session - session key is empty", zap.Stack("stack"))
		}, nil
	}
	unlock, err := c.locks.Lock(ctx, "session:"+id, sessionLockTTL)
	if err != nil {
		return nil, loginTypes.NewInternalError("unable to lock session", err)
	}
	return unlock, nil
}

type LocalSessionStore struct {
	activeLoginSessions                 *sync.Map
	activeInitiateResetPasswordSessions *sync.Map
	activeConfirmResetPasswordSessions  *sync.Map
	activeMFAEnforcementSessions        *sync.Map
	activeUpdateSessions                *sync.Map
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

func (l *LocalSessionStore) CreateMFAEnforcementSession(_ context.Context, key string, user string, rememberUser bool, authenticationResult *AuthenticationResult, expires time.Time) error {
	l.activeMFAEnforcementSessions.Store(key, &MFAEnforcementSession{
		Created:              time.Now(),
		Expires:              expires,
		User:                 user,
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
		activeUpdateSessions:                new(sync.Map),
	}
}

func (l *LocalSessionStore) HasLoginSession(_ context.Context, id string) (bool, error) {
	_, ok := l.activeLoginSessions.Load(id)
	return ok, nil
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

func (l *LocalSessionStore) CreateLoginSession(_ context.Context, csrfToken, id, cognitoSession string, nextStep NextStep, nextStepVariant NextStepVariant, rememberUser bool, expires time.Time, tag any) error {
	l.activeLoginSessions.Store(id,
		&LoginSession{
			CognitoSession:  cognitoSession,
			CSRFToken:       csrfToken,
			Created:         time.Now(),
			Expires:         expires,
			NextStep:        nextStep,
			NextStepVariant: nextStepVariant,
			RememberUser:    rememberUser,
			Tag:             tag})
	return nil
}

func (l *LocalSessionStore) DropLoginSession(_ context.Context, id string) error {
	l.activeLoginSessions.Delete(id)
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

func (l *LocalSessionStore) CreateResetPasswordSession(_ context.Context, id string, user string, email string, expires time.Time) error {
	l.activeInitiateResetPasswordSessions.Store(id, &InitiateResetPasswordSession{
		user,
		email,
		time.Now(),
		expires,
	})
	return nil
}

type RedisSessionStore struct {
	client *redisclient.ClientWrapper
}

const (
	loginSessionPrefix                = "cognito:loginSession:"
	resetPasswordSessionPrefix        = "cognito:resetSession:"
	confirmPasswordResetSessionPrefix = "cognito:confirmResetSession:"
	mfaEnforcementSessionPrefix       = "cognito:mfaEnforcementSession:"
)

func NewRedisSessionStore(client *redisclient.ClientWrapper) *RedisSessionStore {
	return &RedisSessionStore{client: client}
}

//todo: move get\set\drop to generic funcs

func (r *RedisSessionStore) GetConfirmPasswordResetSession(ctx context.Context, id string) (*ConfirmResetPasswordSession, error) {
	clientWrapper := r.client
	client := clientWrapper.Client()

	key := clientWrapper.BuildKey(confirmPasswordResetSessionPrefix, id)
	data, err := client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		getSessionsLogger().Error("failed to get login session from redis",
			zap.String("session", id),
			zap.Error(err))
		return nil, err
	}

	var session ConfirmResetPasswordSession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		getSessionsLogger().Error("failed to unmarshal login session",
			zap.String("session", id),
			zap.Error(err))
		return nil, err
	}

	if session.Created.Before(time.Now()) && session.Expires.After(time.Now()) {
		return &session, nil
	}

	return nil, nil
}

func (r *RedisSessionStore) CreateConfirmPasswordResetSession(ctx context.Context, id string, user string, expires time.Time) error {
	clientWrapper := r.client
	client := clientWrapper.Client()

	key := clientWrapper.BuildKey(confirmPasswordResetSessionPrefix, id)
	session := &ConfirmResetPasswordSession{
		User:    user,
		Created: time.Now(),
		Expires: expires,
	}

	data, err := json.Marshal(session)
	if err != nil {
		getSessionsLogger().Error("failed to marshal login session",
			zap.String("session", id),
			zap.Error(err))
		return err
	}

	ttl := max(time.Until(expires), 0)

	if err := client.Set(ctx, key, data, ttl).Err(); err != nil {
		getSessionsLogger().Error("failed to create login session in redis",
			zap.String("session", id),
			zap.Error(err))
		return err
	}

	getSessionsLogger().Debug("created login session in redis",
		zap.String("session", id),
		zap.Duration("ttl", ttl))

	return nil
}

func (r *RedisSessionStore) DropConfirmPasswordResetSession(ctx context.Context, id string) error {
	clientWrapper := r.client
	client := clientWrapper.Client()

	key := clientWrapper.BuildKey(confirmPasswordResetSessionPrefix, id)
	return client.Del(ctx, key).Err()
}

func (r *RedisSessionStore) GetMFAEnforcementSession(ctx context.Context, id string) (*MFAEnforcementSession, error) {
	clientWrapper := r.client
	client := clientWrapper.Client()

	key := clientWrapper.BuildKey(mfaEnforcementSessionPrefix, id)
	data, err := client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		getSessionsLogger().Error("failed to get MFA enforcement session from redis",
			zap.String("session", id),
			zap.Error(err))
		return nil, err
	}

	var session MFAEnforcementSession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		getSessionsLogger().Error("failed to unmarshal MFA enforcement session",
			zap.String("session", id),
			zap.Error(err))
		return nil, err
	}

	if session.Created.Before(time.Now()) && session.Expires.After(time.Now()) {
		return &session, nil
	}

	return nil, nil
}

func (r *RedisSessionStore) CreateMFAEnforcementSession(ctx context.Context, id string, user string, rememberUser bool, authenticationResult *AuthenticationResult, expires time.Time) error {
	clientWrapper := r.client
	client := clientWrapper.Client()

	key := clientWrapper.BuildKey(mfaEnforcementSessionPrefix, id)
	session := &MFAEnforcementSession{
		Created:              time.Now(),
		Expires:              expires,
		User:                 user,
		RememberUser:         rememberUser,
		AuthenticationResult: authenticationResult,
	}

	data, err := json.Marshal(session)
	if err != nil {
		getSessionsLogger().Error("failed to marshal MFA enforcement session",
			zap.String("session", id),
			zap.Error(err))
		return err
	}

	ttl := max(time.Until(expires), 0)

	if err := client.Set(ctx, key, data, ttl).Err(); err != nil {
		getSessionsLogger().Error("failed to create MFA enforcement session in redis",
			zap.String("session", id),
			zap.Error(err))
		return err
	}

	getSessionsLogger().Debug("created MFA enforcement session in redis",
		zap.String("session", id),
		zap.Duration("ttl", ttl))

	return nil
}

func (r *RedisSessionStore) DropMFAEnforcementSession(ctx context.Context, id string) error {
	clientWrapper := r.client
	client := clientWrapper.Client()

	key := clientWrapper.BuildKey(mfaEnforcementSessionPrefix, id)
	return client.Del(ctx, key).Err()
}

func (r *RedisSessionStore) HasLoginSession(ctx context.Context, id string) (bool, error) {
	clientWrapper := r.client
	client := clientWrapper.Client()
	key := clientWrapper.BuildKey(loginSessionPrefix, id)
	res, err := client.Exists(ctx, key).Result()
	if err != nil {
		getSessionsLogger().Error("failed to get login session from redis",
			zap.String("session", id),
			zap.Error(err))
		return false, err
	}
	return res == 1, nil
}

func (r *RedisSessionStore) GetLoginSession(ctx context.Context, loginSession string) (*LoginSession, error) {
	clientWrapper := r.client
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

func (r *RedisSessionStore) CreateLoginSession(ctx context.Context, csrfToken, id, cognitoSession string, nextStep NextStep, nextStepVariant NextStepVariant, rememberUser bool, expires time.Time, tag any) error {
	clientWrapper := r.client
	client := clientWrapper.Client()

	key := clientWrapper.BuildKey(loginSessionPrefix, id)
	session := &LoginSession{
		CognitoSession:  cognitoSession,
		CSRFToken:       csrfToken,
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
			zap.String("session", id),
			zap.Error(err))
		return err
	}

	ttl := max(time.Until(expires), 0)

	if err := client.Set(ctx, key, data, ttl).Err(); err != nil {
		getSessionsLogger().Error("failed to create login session in redis",
			zap.String("session", id),
			zap.Error(err))
		return err
	}

	getSessionsLogger().Debug("created login session in redis",
		zap.String("session", id),
		zap.Duration("ttl", ttl))

	return nil
}

func (r *RedisSessionStore) DropLoginSession(ctx context.Context, id string) error {
	clientWrapper := r.client
	client := clientWrapper.Client()

	key := clientWrapper.BuildKey(loginSessionPrefix, id)
	return client.Del(ctx, key).Err()
}

func (r *RedisSessionStore) GetResetPasswordSession(ctx context.Context, token string) (*InitiateResetPasswordSession, error) {
	clientWrapper := r.client
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

func (r *RedisSessionStore) CreateResetPasswordSession(ctx context.Context, id string, user string, email string, expires time.Time) error {
	clientWrapper := r.client
	client := clientWrapper.Client()

	key := clientWrapper.BuildKey(resetPasswordSessionPrefix, id)
	session := &InitiateResetPasswordSession{
		User:    user,
		Email:   email,
		Created: time.Now(),
		Expires: expires,
	}

	data, err := json.Marshal(session)
	if err != nil {
		getSessionsLogger().Error("failed to marshal reset password session",
			zap.String("token", id),
			zap.Error(err))
		return err
	}

	ttl := max(time.Until(expires), 0)

	if err := client.Set(ctx, key, data, ttl).Err(); err != nil {
		getSessionsLogger().Error("failed to create reset password session in redis",
			zap.String("token", id),
			zap.Error(err))
		return err
	}

	getSessionsLogger().Debug("created reset password session in redis",
		zap.String("token", id),
		zap.Duration("ttl", ttl))

	return nil
}

func (r *RedisSessionStore) DropResetPasswordSession(ctx context.Context, token string) error {
	clientWrapper := r.client
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

func (c *Cognito) reserveNewLoginSessionId(ctx context.Context) (string, func(), loginTypes.GenericError) {
	return c.reserveNewSessionId(ctx, c.sessionStorage.HasLoginSession)
}

func (c *Cognito) reserveNewUpdateSessionId(ctx context.Context) (string, func(), loginTypes.GenericError) {
	return c.reserveNewSessionId(ctx, c.sessionStorage.HasUpdateSession)
}

// reserveNewSessionId generates an unused session id and returns it locked.
func (c *Cognito) reserveNewSessionId(ctx context.Context, exists func(ctx context.Context, id string) (bool, error)) (string, func(), loginTypes.GenericError) {
	var loginSessionId string
	var unlockSession func()

	for {
		var err error
		loginSessionId, err = tools.GenerateRandomString(32)
		if err != nil {
			return "", nil, loginTypes.NewInternalError("failed to generate new login session id", err)
		}
		var lockErr loginTypes.GenericError
		unlockSession, lockErr = c.lockSession(ctx, loginSessionId)
		if lockErr != nil {
			return "", nil, lockErr
		}
		taken, err := exists(ctx, loginSessionId)
		if err != nil {
			unlockSession()
			return "", nil, loginTypes.NewInternalError("failed to check if login session exists", err)
		}
		if err = ctx.Err(); err != nil {
			unlockSession()
			return "", nil, loginTypes.NewInternalError("failed to check if login session exists", err) //todo: maybe use another error
		}
		if taken {
			unlockSession()
		} else {
			break
		}
	}

	return loginSessionId, unlockSession, nil
}
