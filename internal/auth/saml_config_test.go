package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testCertPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func validSAMLInput(t *testing.T) SAMLConfigInput {
	return SAMLConfigInput{
		Name:           "社内ADFS",
		IdPEntityID:    "https://adfs.example.com/adfs/services/trust",
		IdPSSOURL:      "https://adfs.example.com/adfs/ls/",
		IdPCertificate: testCertPEM(t),
		EmailAttribute: "email",
		Trusted:        true,
		Enabled:        true,
	}
}

func TestSAMLConfigInput_Normalize(t *testing.T) {
	t.Run("valid input passes", func(t *testing.T) {
		if _, err := validSAMLInput(t).normalize(); err != nil {
			t.Fatalf("expected valid input to pass, got %v", err)
		}
	})

	t.Run("empty name is rejected", func(t *testing.T) {
		in := validSAMLInput(t)
		in.Name = "  "
		if _, err := in.normalize(); !errors.Is(err, ErrInvalidSAMLConfig) {
			t.Fatalf("expected ErrInvalidSAMLConfig, got %v", err)
		}
	})

	t.Run("empty idp_entity_id is rejected", func(t *testing.T) {
		in := validSAMLInput(t)
		in.IdPEntityID = ""
		if _, err := in.normalize(); !errors.Is(err, ErrInvalidSAMLConfig) {
			t.Fatalf("expected ErrInvalidSAMLConfig, got %v", err)
		}
	})

	t.Run("empty email_attribute is rejected", func(t *testing.T) {
		in := validSAMLInput(t)
		in.EmailAttribute = ""
		if _, err := in.normalize(); !errors.Is(err, ErrInvalidSAMLConfig) {
			t.Fatalf("expected ErrInvalidSAMLConfig, got %v", err)
		}
	})

	t.Run("non-http(s) sso url is rejected", func(t *testing.T) {
		in := validSAMLInput(t)
		in.IdPSSOURL = "ftp://adfs.example.com/ls/"
		if _, err := in.normalize(); !errors.Is(err, ErrInvalidSAMLConfig) {
			t.Fatalf("expected ErrInvalidSAMLConfig, got %v", err)
		}
	})

	t.Run("malformed sso url is rejected", func(t *testing.T) {
		in := validSAMLInput(t)
		in.IdPSSOURL = "not a url"
		if _, err := in.normalize(); !errors.Is(err, ErrInvalidSAMLConfig) {
			t.Fatalf("expected ErrInvalidSAMLConfig, got %v", err)
		}
	})

	t.Run("non-PEM certificate is rejected", func(t *testing.T) {
		in := validSAMLInput(t)
		in.IdPCertificate = "not a certificate"
		if _, err := in.normalize(); !errors.Is(err, ErrInvalidSAMLConfig) {
			t.Fatalf("expected ErrInvalidSAMLConfig, got %v", err)
		}
	})

	t.Run("PEM block that isn't a valid X.509 certificate is rejected", func(t *testing.T) {
		in := validSAMLInput(t)
		in.IdPCertificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not asn1")}))
		if _, err := in.normalize(); !errors.Is(err, ErrInvalidSAMLConfig) {
			t.Fatalf("expected ErrInvalidSAMLConfig, got %v", err)
		}
	})

	t.Run("surrounding whitespace is trimmed", func(t *testing.T) {
		in := validSAMLInput(t)
		in.Name = "  社内ADFS  "
		normalized, err := in.normalize()
		if err != nil {
			t.Fatalf("normalize: %v", err)
		}
		if normalized.Name != "社内ADFS" {
			t.Fatalf("expected trimmed name, got %q", normalized.Name)
		}
	})
}

type fakeSAMLConfigStore struct {
	configs    map[uuid.UUID]*SAMLConfig
	identCount map[uuid.UUID]int
}

func newFakeSAMLConfigStore() *fakeSAMLConfigStore {
	return &fakeSAMLConfigStore{configs: map[uuid.UUID]*SAMLConfig{}, identCount: map[uuid.UUID]int{}}
}

func (s *fakeSAMLConfigStore) ListSAMLConfigs(context.Context) ([]*SAMLConfig, error) {
	result := make([]*SAMLConfig, 0, len(s.configs))
	for _, c := range s.configs {
		result = append(result, c)
	}
	return result, nil
}

func (s *fakeSAMLConfigStore) FindSAMLConfigByID(_ context.Context, id uuid.UUID) (*SAMLConfig, error) {
	c, ok := s.configs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return c, nil
}

func (s *fakeSAMLConfigStore) CreateSAMLConfig(_ context.Context, in SAMLConfigInput) (*SAMLConfig, error) {
	c := &SAMLConfig{
		ID: uuid.New(), Name: in.Name, IdPEntityID: in.IdPEntityID, IdPSSOURL: in.IdPSSOURL,
		IdPCertificate: in.IdPCertificate, EmailAttribute: in.EmailAttribute, Trusted: in.Trusted, Enabled: in.Enabled,
	}
	s.configs[c.ID] = c
	return c, nil
}

func (s *fakeSAMLConfigStore) UpdateSAMLConfig(_ context.Context, id uuid.UUID, in SAMLConfigInput) (*SAMLConfig, error) {
	if _, ok := s.configs[id]; !ok {
		return nil, ErrNotFound
	}
	c := &SAMLConfig{
		ID: id, Name: in.Name, IdPEntityID: in.IdPEntityID, IdPSSOURL: in.IdPSSOURL,
		IdPCertificate: in.IdPCertificate, EmailAttribute: in.EmailAttribute, Trusted: in.Trusted, Enabled: in.Enabled,
	}
	s.configs[id] = c
	return c, nil
}

func (s *fakeSAMLConfigStore) DeleteSAMLConfig(_ context.Context, id uuid.UUID) error {
	if _, ok := s.configs[id]; !ok {
		return ErrNotFound
	}
	delete(s.configs, id)
	return nil
}

func (s *fakeSAMLConfigStore) CountAuthIdentitiesForSAMLConfig(_ context.Context, id uuid.UUID) (int, error) {
	return s.identCount[id], nil
}

func TestSAMLConfigService_CreateRejectsInvalidInputBeforeHittingStore(t *testing.T) {
	store := newFakeSAMLConfigStore()
	svc := &SAMLConfigService{Store: store}

	in := validSAMLInput(t)
	in.Name = ""
	if _, err := svc.Create(context.Background(), in); !errors.Is(err, ErrInvalidSAMLConfig) {
		t.Fatalf("expected ErrInvalidSAMLConfig, got %v", err)
	}
	if len(store.configs) != 0 {
		t.Fatalf("expected the store to be untouched on validation failure, got %+v", store.configs)
	}
}

func TestSAMLConfigService_CreateAndUpdate(t *testing.T) {
	store := newFakeSAMLConfigStore()
	svc := &SAMLConfigService{Store: store}
	ctx := context.Background()

	created, err := svc.Create(ctx, validSAMLInput(t))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	update := validSAMLInput(t)
	update.Name = "更新後の名前"
	updated, err := svc.Update(ctx, created.ID, update)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Name != "更新後の名前" {
		t.Fatalf("expected the name to be updated, got %+v", updated)
	}

	if _, err := svc.Update(ctx, uuid.New(), validSAMLInput(t)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for an unknown id, got %v", err)
	}
}

func TestSAMLConfigService_DeleteRefusesWhenInUse(t *testing.T) {
	store := newFakeSAMLConfigStore()
	svc := &SAMLConfigService{Store: store}
	ctx := context.Background()

	created, err := svc.Create(ctx, validSAMLInput(t))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	store.identCount[created.ID] = 1

	if err := svc.Delete(ctx, created.ID); !errors.Is(err, ErrSAMLConfigInUse) {
		t.Fatalf("expected ErrSAMLConfigInUse, got %v", err)
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
