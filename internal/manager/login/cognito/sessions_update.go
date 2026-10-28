package cognito

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// UpdateStep is the next expected step of an authenticated update flow (password or MFA update).
type UpdateStep string

const (
	UpdateStepPasswordUpdate               UpdateStep = "password_update"
	UpdateStepMFASoftwareTokenUpdate       UpdateStep = "mfa_software_token_update"
	UpdateStepMFASoftwareTokenUpdateVerify UpdateStep = "mfa_software_token_update_verify"
)

const updateSessionPrefix = "cognito:updateSession:"

// UpdateSession guards an authenticated update flow. It is bound to the user
// that started it and to a CSRF token handed out by the flow's start endpoint.
type UpdateSession struct {
	CSRFToken string     `json:"csrf_token"`
	Subject   string     `json:"subject"`
	Step      UpdateStep `json:"step"`
	Created   time.Time  `json:"created"`
	Expires   time.Time  `json:"expires"`
}

func (u UpdateSession) GetStartTime() time.Time {
	return u.Created
}

func (u UpdateSession) GetExpirationTime() time.Time {
	return u.Expires
}

func (u *UpdateSession) isActive() bool {
	now := time.Now()
	return u.Created.Before(now) && u.Expires.After(now)
}

func (c *Cognito) newUpdateSession(csrfToken, subject string, step UpdateStep) *UpdateSession {
	now := time.Now()
	return &UpdateSession{
		CSRFToken: csrfToken,
		Subject:   subject,
		Step:      step,
		Created:   now,
		Expires:   now.Add(c.loginSessionValidFor),
	}
}

func (l *LocalSessionStore) HasUpdateSession(_ context.Context, id string) (bool, error) {
	_, ok := l.activeUpdateSessions.Load(id)
	return ok, nil
}

func (l *LocalSessionStore) GetUpdateSession(_ context.Context, id string) (*UpdateSession, error) {
	r, ok := l.activeUpdateSessions.Load(id)
	if ok && r != nil {
		if s := r.(*UpdateSession); s.isActive() {
			return s, nil
		}
	}
	return nil, nil
}

func (l *LocalSessionStore) CreateUpdateSession(_ context.Context, id string, session *UpdateSession) error {
	l.activeUpdateSessions.Store(id, session)
	return nil
}

func (l *LocalSessionStore) DropUpdateSession(_ context.Context, id string) error {
	l.activeUpdateSessions.Delete(id)
	return nil
}

func (r *RedisSessionStore) HasUpdateSession(ctx context.Context, id string) (bool, error) {
	key := r.client.BuildKey(updateSessionPrefix, id)
	res, err := r.client.Client().Exists(ctx, key).Result()
	if err != nil {
		getSessionsLogger().Error("failed to check update session in redis", zap.String("session", id), zap.Error(err))
		return false, err
	}
	return res == 1, nil
}

func (r *RedisSessionStore) GetUpdateSession(ctx context.Context, id string) (*UpdateSession, error) {
	key := r.client.BuildKey(updateSessionPrefix, id)
	data, err := r.client.Client().Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		getSessionsLogger().Error("failed to get update session from redis", zap.String("session", id), zap.Error(err))
		return nil, err
	}

	var session UpdateSession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		getSessionsLogger().Error("failed to unmarshal update session", zap.String("session", id), zap.Error(err))
		return nil, err
	}

	if session.isActive() {
		return &session, nil
	}
	return nil, nil
}

func (r *RedisSessionStore) CreateUpdateSession(ctx context.Context, id string, session *UpdateSession) error {
	data, err := json.Marshal(session)
	if err != nil {
		getSessionsLogger().Error("failed to marshal update session", zap.String("session", id), zap.Error(err))
		return err
	}

	ttl := max(time.Until(session.Expires), 0)

	key := r.client.BuildKey(updateSessionPrefix, id)
	if err := r.client.Client().Set(ctx, key, data, ttl).Err(); err != nil {
		getSessionsLogger().Error("failed to create update session in redis", zap.String("session", id), zap.Error(err))
		return err
	}
	return nil
}

func (r *RedisSessionStore) DropUpdateSession(ctx context.Context, id string) error {
	key := r.client.BuildKey(updateSessionPrefix, id)
	return r.client.Client().Del(ctx, key).Err()
}
