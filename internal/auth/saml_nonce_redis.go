package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	samlRequestKeyPrefix   = "saml_request:"
	samlAssertionKeyPrefix = "saml_assertion:"
)

// RedisSAMLNonceStore is the production SAMLNonceStore implementation —
// Redis, matching RedisSessionStore's operational choice (immediate
// expiry, no cross-restart persistence needed for short-lived login
// transactions).
type RedisSAMLNonceStore struct {
	redis *redis.Client
}

var _ SAMLNonceStore = (*RedisSAMLNonceStore)(nil)

func NewRedisSAMLNonceStore(client *redis.Client) *RedisSAMLNonceStore {
	return &RedisSAMLNonceStore{redis: client}
}

func (s *RedisSAMLNonceStore) CreateRequest(ctx context.Context, relayState string, configID uuid.UUID, ttl time.Duration) error {
	return s.redis.Set(ctx, samlRequestKeyPrefix+relayState, configID.String(), ttl).Err()
}

func (s *RedisSAMLNonceStore) ConsumeRequest(ctx context.Context, relayState string) (uuid.UUID, bool, error) {
	val, err := s.redis.GetDel(ctx, samlRequestKeyPrefix+relayState).Result()
	if errors.Is(err, redis.Nil) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, err
	}
	configID, err := uuid.Parse(val)
	if err != nil {
		return uuid.Nil, false, err
	}
	return configID, true, nil
}

func (s *RedisSAMLNonceStore) MarkAssertionSeen(ctx context.Context, assertionID string, ttl time.Duration) (bool, error) {
	wasSet, err := s.redis.SetNX(ctx, samlAssertionKeyPrefix+assertionID, "1", ttl).Result()
	if err != nil {
		return false, err
	}
	return !wasSet, nil
}
