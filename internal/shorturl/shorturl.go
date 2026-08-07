package shorturl

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// maxRandomCodeAttempts bounds retries when a randomly generated code
// collides with an existing one for the same domain. A real collision at
// this rate would indicate the configured charset/length is far too small
// for the domain's URL count, not ordinary bad luck.
const maxRandomCodeAttempts = 5

var (
	ErrNotFound       = errors.New("shorturl: not found")
	ErrInvalidLongURL = errors.New("shorturl: long_url must be an absolute http(s) URL")
	ErrInvalidAlias   = errors.New("shorturl: alias must be 1-64 characters of letters, digits, '-', '_' or '.'")
	ErrAliasTaken     = errors.New("shorturl: alias is already in use for this domain")

	// ErrCodeCollision is returned by Store.CreateShortURL when
	// (DomainID, ShortCode) already exists (the UNIQUE(domain_id,
	// short_code) constraint, 2.2節). Create retries with a new random
	// code on it; a custom alias collision is surfaced as ErrAliasTaken
	// instead, since there is nothing else to retry with.
	ErrCodeCollision = errors.New("shorturl: short_code collision")
)

type Status string

const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"
	StatusExpired  Status = "expired"
)

type Source string

const (
	SourceNative       Source = "native"
	SourceYOURLSImport Source = "yourls_import"
)

type ShortURL struct {
	ID          uuid.UUID
	DomainID    uuid.UUID
	ShortCode   string
	LongURL     string
	Title       string
	Description string
	CreatedBy   uuid.UUID
	Status      Status
	ExpiresAt   *time.Time
	Source      Source
}

// CreateInput is the caller-supplied part of creating a short URL.
// CustomAlias empty means "generate a random code" (2.2節・Context節).
type CreateInput struct {
	DomainID    uuid.UUID
	CustomAlias string
	LongURL     string
	Title       string
	Description string
	CreatedBy   uuid.UUID
	ExpiresAt   *time.Time
}

// Store is the persistence port Create depends on.
type Store interface {
	// ShortCodeSettings returns the current random-generation policy.
	// Callers must fetch it fresh per Create call rather than cache it:
	// a settings change only applies to new random generations, never
	// retroactively (2.2節), so a stale cached value would misrepresent
	// "current policy".
	ShortCodeSettings(ctx context.Context) (charset string, length int, err error)

	// CreateShortURL inserts the short_urls row and, in the same
	// transaction, grants CreatedBy the owner role in url_permissions —
	// a short URL must never exist without an owner (4.2節: 作成時に
	// 作成者が自動的にownerとなる). It returns ErrCodeCollision if
	// (in.DomainID, in.ShortCode) is already taken.
	CreateShortURL(ctx context.Context, in ShortURL) (*ShortURL, error)

	// FindByID returns ErrNotFound if no short URL with that id exists.
	FindByID(ctx context.Context, id uuid.UUID) (*ShortURL, error)
}

type Creator struct {
	Store Store
	// RandomCode generates one candidate code from a charset/length pair;
	// defaults to a crypto/rand-backed generator. Override in tests for a
	// deterministic sequence.
	RandomCode func(charset string, length int) (string, error)
}

func (c *Creator) randomCode(charset string, length int) (string, error) {
	if c.RandomCode != nil {
		return c.RandomCode(charset, length)
	}
	return randomCode(charset, length)
}

// Create validates the long URL and either uses the caller's custom alias
// or generates a random short_code per short_code_settings, retrying on
// collision.
func (c *Creator) Create(ctx context.Context, in CreateInput) (*ShortURL, error) {
	longURL, err := normalizeLongURL(in.LongURL)
	if err != nil {
		return nil, err
	}

	if in.CustomAlias != "" {
		alias, err := normalizeAlias(in.CustomAlias)
		if err != nil {
			return nil, err
		}
		su, err := c.insert(ctx, in, longURL, alias)
		if errors.Is(err, ErrCodeCollision) {
			return nil, ErrAliasTaken
		}
		return su, err
	}

	charset, length, err := c.Store.ShortCodeSettings(ctx)
	if err != nil {
		return nil, err
	}

	for attempt := 0; attempt < maxRandomCodeAttempts; attempt++ {
		code, err := c.randomCode(charset, length)
		if err != nil {
			return nil, err
		}
		su, err := c.insert(ctx, in, longURL, code)
		if errors.Is(err, ErrCodeCollision) {
			continue
		}
		return su, err
	}
	return nil, fmt.Errorf("shorturl: exhausted %d random code generation attempts", maxRandomCodeAttempts)
}

func (c *Creator) insert(ctx context.Context, in CreateInput, longURL, code string) (*ShortURL, error) {
	return c.Store.CreateShortURL(ctx, ShortURL{
		DomainID:    in.DomainID,
		ShortCode:   code,
		LongURL:     longURL,
		Title:       in.Title,
		Description: in.Description,
		CreatedBy:   in.CreatedBy,
		Status:      StatusActive,
		ExpiresAt:   in.ExpiresAt,
		Source:      SourceNative,
	})
}

func normalizeLongURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", ErrInvalidLongURL
	}
	u, err := url.Parse(trimmed)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", ErrInvalidLongURL
	}
	return trimmed, nil
}

var aliasPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func normalizeAlias(raw string) (string, error) {
	alias := strings.TrimSpace(raw)
	if !aliasPattern.MatchString(alias) {
		return "", ErrInvalidAlias
	}
	return alias, nil
}

// randomCode draws length characters uniformly from charset using
// crypto/rand (short codes are guessable-security-relevant, unlike e.g. UI
// labels, so a non-cryptographic RNG would be the wrong default here).
func randomCode(charset string, length int) (string, error) {
	if len(charset) == 0 || length <= 0 {
		return "", fmt.Errorf("shorturl: invalid short_code_settings (charset length=%d, code length=%d)", len(charset), length)
	}
	max := big.NewInt(int64(len(charset)))
	code := make([]byte, length)
	for i := range code {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		code[i] = charset[n.Int64()]
	}
	return string(code), nil
}
