package auth

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

const oidcStateKeyPrefix = "oidc_state:"

// RedisOIDCNonceStore is the production OIDCNonceStore implementation —
// Redis, matching RedisSessionStore/RedisSAMLNonceStore's operational
// choice for short-lived login transactions.
type RedisOIDCNonceStore struct {
	redis *redis.Client
}

var _ OIDCNonceStore = (*RedisOIDCNonceStore)(nil)

func NewRedisOIDCNonceStore(client *redis.Client) *RedisOIDCNonceStore {
	return &RedisOIDCNonceStore{redis: client}
}

func (s *RedisOIDCNonceStore) CreateState(ctx context.Context, state string, pending OIDCPendingLogin, ttl time.Duration) error {
	data, err := json.Marshal(pending)
	if err != nil {
		return err
	}
	return s.redis.Set(ctx, oidcStateKeyPrefix+state, data, ttl).Err()
}

func (s *RedisOIDCNonceStore) ConsumeState(ctx context.Context, state string) (OIDCPendingLogin, bool, error) {
	data, err := s.redis.GetDel(ctx, oidcStateKeyPrefix+state).Bytes()
	if errors.Is(err, redis.Nil) {
		return OIDCPendingLogin{}, false, nil
	}
	if err != nil {
		return OIDCPendingLogin{}, false, err
	}
	var pending OIDCPendingLogin
	if err := json.Unmarshal(data, &pending); err != nil {
		return OIDCPendingLogin{}, false, err
	}
	return pending, true, nil
}
