package auth

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var ErrSessionNotFound = errors.New("auth: session not found")

// Session is a single authenticated login (5.2節: Cookie + サーバサイド
// セッション). The cookie carries only the raw token; everything else
// lives server-side so a session can be inspected or revoked without
// trusting the client.
type Session struct {
	UserID     uuid.UUID
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
}

// SessionStore issues and validates server-side sessions. The operational
// choice here is Redis, not PostgreSQL (5.2節: 即時失効のしやすさを優先
// するため) — RedisSessionStore below is the only production
// implementation; the interface exists for cmd/api's HTTP layer to depend
// on something fakeable in tests.
type SessionStore interface {
	// Create issues a new session for userID and returns the raw token to
	// set as the session cookie's value. Only a hash of it is persisted,
	// mirroring pending_link_requests.token_hash and sessions.id(hash).
	Create(ctx context.Context, userID uuid.UUID, ttl time.Duration) (token string, err error)
	// Find resolves a raw token (as read from the cookie) to its session,
	// or ErrSessionNotFound if it doesn't exist or has expired.
	Find(ctx context.Context, token string) (*Session, error)
	// Touch extends a session's expiry and refreshes LastSeenAt — called
	// on each authenticated request to implement a sliding-window TTL.
	Touch(ctx context.Context, token string, ttl time.Duration) error
	// Delete revokes a single session (logout). Deleting an
	// already-gone token is not an error.
	Delete(ctx context.Context, token string) error
	// DeleteAllForUser revokes every session for userID at once — the
	// "退職者対応やなりすまし検知時に即座に権限を剥奪できる" requirement
	// this whole session design was chosen over JWT for (5.2節).
	DeleteAllForUser(ctx context.Context, userID uuid.UUID) error
}

const (
	sessionKeyPrefix      = "session:"
	userSessionsKeyPrefix = "user_sessions:"
)

// sessionRecord is the JSON shape stored in Redis under sessionKeyPrefix.
type sessionRecord struct {
	UserID     uuid.UUID `json:"user_id"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

type RedisSessionStore struct {
	redis *redis.Client
}

var _ SessionStore = (*RedisSessionStore)(nil)

func NewRedisSessionStore(client *redis.Client) *RedisSessionStore {
	return &RedisSessionStore{redis: client}
}

func (s *RedisSessionStore) Create(ctx context.Context, userID uuid.UUID, ttl time.Duration) (string, error) {
	raw, hash, err := generateToken()
	if err != nil {
		return "", err
	}

	now := time.Now()
	data, err := json.Marshal(sessionRecord{UserID: userID, CreatedAt: now, ExpiresAt: now.Add(ttl), LastSeenAt: now})
	if err != nil {
		return "", err
	}

	userSessionsKey := userSessionsKeyPrefix + userID.String()
	pipe := s.redis.TxPipeline()
	pipe.Set(ctx, sessionKeyPrefix+hash, data, ttl)
	pipe.SAdd(ctx, userSessionsKey, hash)
	// このsetは「ユーザの全セッションを列挙してDeleteAllForUserする」ためだけ
	// の索引なので、個々のセッションと同じTTLで転がしておけば十分。
	pipe.Expire(ctx, userSessionsKey, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return "", err
	}
	return raw, nil
}

func (s *RedisSessionStore) Find(ctx context.Context, token string) (*Session, error) {
	rec, err := s.get(ctx, hashToken(token))
	if err != nil {
		return nil, err
	}
	return &Session{UserID: rec.UserID, CreatedAt: rec.CreatedAt, ExpiresAt: rec.ExpiresAt, LastSeenAt: rec.LastSeenAt}, nil
}

func (s *RedisSessionStore) Touch(ctx context.Context, token string, ttl time.Duration) error {
	hash := hashToken(token)
	rec, err := s.get(ctx, hash)
	if err != nil {
		return err
	}

	rec.LastSeenAt = time.Now()
	rec.ExpiresAt = rec.LastSeenAt.Add(ttl)
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	userSessionsKey := userSessionsKeyPrefix + rec.UserID.String()
	pipe := s.redis.TxPipeline()
	pipe.Set(ctx, sessionKeyPrefix+hash, data, ttl)
	pipe.Expire(ctx, userSessionsKey, ttl)
	_, err = pipe.Exec(ctx)
	return err
}

func (s *RedisSessionStore) Delete(ctx context.Context, token string) error {
	hash := hashToken(token)
	rec, err := s.get(ctx, hash)
	if errors.Is(err, ErrSessionNotFound) {
		return nil
	}
	if err != nil {
		return err
	}

	pipe := s.redis.TxPipeline()
	pipe.Del(ctx, sessionKeyPrefix+hash)
	pipe.SRem(ctx, userSessionsKeyPrefix+rec.UserID.String(), hash)
	_, err = pipe.Exec(ctx)
	return err
}

func (s *RedisSessionStore) DeleteAllForUser(ctx context.Context, userID uuid.UUID) error {
	userSessionsKey := userSessionsKeyPrefix + userID.String()
	hashes, err := s.redis.SMembers(ctx, userSessionsKey).Result()
	if err != nil {
		return err
	}
	if len(hashes) == 0 {
		return nil
	}

	keys := make([]string, len(hashes))
	for i, h := range hashes {
		keys[i] = sessionKeyPrefix + h
	}
	pipe := s.redis.TxPipeline()
	pipe.Del(ctx, keys...)
	pipe.Del(ctx, userSessionsKey)
	_, err = pipe.Exec(ctx)
	return err
}

func (s *RedisSessionStore) get(ctx context.Context, hash string) (*sessionRecord, error) {
	data, err := s.redis.Get(ctx, sessionKeyPrefix+hash).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	var rec sessionRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}
