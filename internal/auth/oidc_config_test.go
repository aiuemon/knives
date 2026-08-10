package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func validOIDCInput() OIDCConfigInput {
	return OIDCConfigInput{
		Name:                      "社内Entra ID",
		Issuer:                    "https://login.microsoftonline.com/tenant-id/v2.0",
		ClientID:                  "client-abc",
		ClientSecret:              "s3cr3t",
		Scopes:                    []string{"openid", "email", "profile"},
		RequireEmailVerifiedClaim: true,
		Enabled:                   true,
	}
}

func TestOIDCConfigInput_Normalize(t *testing.T) {
	t.Run("valid input passes on create", func(t *testing.T) {
		if _, err := validOIDCInput().normalize(true); err != nil {
			t.Fatalf("expected valid input to pass, got %v", err)
		}
	})

	t.Run("empty name is rejected", func(t *testing.T) {
		in := validOIDCInput()
		in.Name = "  "
		if _, err := in.normalize(true); !errors.Is(err, ErrInvalidOIDCConfig) {
			t.Fatalf("expected ErrInvalidOIDCConfig, got %v", err)
		}
	})

	t.Run("empty client_id is rejected", func(t *testing.T) {
		in := validOIDCInput()
		in.ClientID = ""
		if _, err := in.normalize(true); !errors.Is(err, ErrInvalidOIDCConfig) {
			t.Fatalf("expected ErrInvalidOIDCConfig, got %v", err)
		}
	})

	t.Run("empty client_secret is rejected on create", func(t *testing.T) {
		in := validOIDCInput()
		in.ClientSecret = ""
		if _, err := in.normalize(true); !errors.Is(err, ErrInvalidOIDCConfig) {
			t.Fatalf("expected ErrInvalidOIDCConfig, got %v", err)
		}
	})

	t.Run("empty client_secret is allowed on update (keep existing)", func(t *testing.T) {
		in := validOIDCInput()
		in.ClientSecret = ""
		normalized, err := in.normalize(false)
		if err != nil {
			t.Fatalf("expected empty client_secret to be allowed on update, got %v", err)
		}
		if normalized.ClientSecret != "" {
			t.Fatalf("expected ClientSecret to stay empty (meaning: keep existing), got %q", normalized.ClientSecret)
		}
	})

	t.Run("non-http(s) issuer is rejected", func(t *testing.T) {
		in := validOIDCInput()
		in.Issuer = "not a url"
		if _, err := in.normalize(true); !errors.Is(err, ErrInvalidOIDCConfig) {
			t.Fatalf("expected ErrInvalidOIDCConfig, got %v", err)
		}
	})

	t.Run("scopes without openid are rejected", func(t *testing.T) {
		in := validOIDCInput()
		in.Scopes = []string{"email", "profile"}
		if _, err := in.normalize(true); !errors.Is(err, ErrInvalidOIDCConfig) {
			t.Fatalf("expected ErrInvalidOIDCConfig for scopes missing openid, got %v", err)
		}
	})

	t.Run("empty/whitespace scope entries are dropped", func(t *testing.T) {
		in := validOIDCInput()
		in.Scopes = []string{"openid", "  ", "", "email"}
		normalized, err := in.normalize(true)
		if err != nil {
			t.Fatalf("normalize: %v", err)
		}
		if len(normalized.Scopes) != 2 {
			t.Fatalf("expected blank scope entries to be dropped, got %+v", normalized.Scopes)
		}
	})
}

type fakeOIDCConfigStore struct {
	configs    map[uuid.UUID]*OIDCConfig
	identCount map[uuid.UUID]int
}

func newFakeOIDCConfigStore() *fakeOIDCConfigStore {
	return &fakeOIDCConfigStore{configs: map[uuid.UUID]*OIDCConfig{}, identCount: map[uuid.UUID]int{}}
}

func (s *fakeOIDCConfigStore) ListOIDCConfigs(context.Context) ([]*OIDCConfig, error) {
	result := make([]*OIDCConfig, 0, len(s.configs))
	for _, c := range s.configs {
		result = append(result, c)
	}
	return result, nil
}

func (s *fakeOIDCConfigStore) FindOIDCConfigByID(_ context.Context, id uuid.UUID) (*OIDCConfig, error) {
	c, ok := s.configs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return c, nil
}

func (s *fakeOIDCConfigStore) CreateOIDCConfig(_ context.Context, in OIDCConfigInput) (*OIDCConfig, error) {
	c := &OIDCConfig{
		ID: uuid.New(), Name: in.Name, Issuer: in.Issuer, ClientID: in.ClientID,
		ClientSecret: in.ClientSecret, Scopes: in.Scopes,
		RequireEmailVerifiedClaim: in.RequireEmailVerifiedClaim, Enabled: in.Enabled,
	}
	s.configs[c.ID] = c
	return c, nil
}

func (s *fakeOIDCConfigStore) UpdateOIDCConfig(_ context.Context, id uuid.UUID, in OIDCConfigInput) (*OIDCConfig, error) {
	existing, ok := s.configs[id]
	if !ok {
		return nil, ErrNotFound
	}
	secret := existing.ClientSecret
	if in.ClientSecret != "" {
		secret = in.ClientSecret
	}
	c := &OIDCConfig{
		ID: id, Name: in.Name, Issuer: in.Issuer, ClientID: in.ClientID,
		ClientSecret: secret, Scopes: in.Scopes,
		RequireEmailVerifiedClaim: in.RequireEmailVerifiedClaim, Enabled: in.Enabled,
	}
	s.configs[id] = c
	return c, nil
}

func (s *fakeOIDCConfigStore) DeleteOIDCConfig(_ context.Context, id uuid.UUID) error {
	if _, ok := s.configs[id]; !ok {
		return ErrNotFound
	}
	delete(s.configs, id)
	return nil
}

func (s *fakeOIDCConfigStore) CountAuthIdentitiesForOIDCConfig(_ context.Context, id uuid.UUID) (int, error) {
	return s.identCount[id], nil
}

func TestOIDCConfigService_CreateRejectsInvalidInputBeforeHittingStore(t *testing.T) {
	store := newFakeOIDCConfigStore()
	svc := &OIDCConfigService{Store: store}

	in := validOIDCInput()
	in.Name = ""
	if _, err := svc.Create(context.Background(), in); !errors.Is(err, ErrInvalidOIDCConfig) {
		t.Fatalf("expected ErrInvalidOIDCConfig, got %v", err)
	}
	if len(store.configs) != 0 {
		t.Fatalf("expected the store to be untouched on validation failure, got %+v", store.configs)
	}
}

func TestOIDCConfigService_UpdateWithoutSecretKeepsExisting(t *testing.T) {
	store := newFakeOIDCConfigStore()
	svc := &OIDCConfigService{Store: store}
	ctx := context.Background()

	created, err := svc.Create(ctx, validOIDCInput())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	update := validOIDCInput()
	update.Name = "更新後の名前"
	update.ClientSecret = ""
	updated, err := svc.Update(ctx, created.ID, update)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Name != "更新後の名前" {
		t.Fatalf("expected the name to be updated, got %+v", updated)
	}
	if updated.ClientSecret != created.ClientSecret {
		t.Fatalf("expected the client secret to be preserved when not resent, got %q want %q", updated.ClientSecret, created.ClientSecret)
	}

	if _, err := svc.Update(ctx, uuid.New(), validOIDCInput()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for an unknown id, got %v", err)
	}
}

func TestOIDCConfigService_UpdateWithNewSecretRotatesIt(t *testing.T) {
	store := newFakeOIDCConfigStore()
	svc := &OIDCConfigService{Store: store}
	ctx := context.Background()

	created, err := svc.Create(ctx, validOIDCInput())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	update := validOIDCInput()
	update.ClientSecret = "rotated-secret"
	updated, err := svc.Update(ctx, created.ID, update)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.ClientSecret != "rotated-secret" {
		t.Fatalf("expected the client secret to be rotated, got %q", updated.ClientSecret)
	}
}

func TestOIDCConfigService_DeleteRefusesWhenInUse(t *testing.T) {
	store := newFakeOIDCConfigStore()
	svc := &OIDCConfigService{Store: store}
	ctx := context.Background()

	created, err := svc.Create(ctx, validOIDCInput())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	store.identCount[created.ID] = 1

	if err := svc.Delete(ctx, created.ID); !errors.Is(err, ErrOIDCConfigInUse) {
		t.Fatalf("expected ErrOIDCConfigInUse, got %v", err)
	}
	if _, ok := store.configs[created.ID]; !ok {
		t.Fatalf("expected the config to remain after a refused delete")
	}

	store.identCount[created.ID] = 0
	if err := svc.Delete(ctx, created.ID); err != nil {
		t.Fatalf("expected delete to succeed once unused, got %v", err)
	}
	if _, ok := store.configs[created.ID]; ok {
		t.Fatalf("expected the config to be removed")
	}
}
