package auth

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

const webauthnSessionKeyPrefix = "webauthn_session:"

// RedisWebAuthnSessionStore is the production WebAuthnSessionStore
// implementation — Redis, matching RedisSessionStore/RedisSAMLNonceStore's
// operational choice (immediate expiry, no cross-restart persistence
// needed for a short-lived ceremony).
type RedisWebAuthnSessionStore struct {
	redis *redis.Client
}

var _ WebAuthnSessionStore = (*RedisWebAuthnSessionStore)(nil)

func NewRedisWebAuthnSessionStore(client *redis.Client) *RedisWebAuthnSessionStore {
	return &RedisWebAuthnSessionStore{redis: client}
}

func (s *RedisWebAuthnSessionStore) Create(ctx context.Context, ceremonyID string, data []byte, ttl time.Duration) error {
	return s.redis.Set(ctx, webauthnSessionKeyPrefix+ceremonyID, data, ttl).Err()
}

func (s *RedisWebAuthnSessionStore) Consume(ctx context.Context, ceremonyID string) ([]byte, bool, error) {
	val, err := s.redis.GetDel(ctx, webauthnSessionKeyPrefix+ceremonyID).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return val, true, nil
}
