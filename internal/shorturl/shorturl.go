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

// UpdateInput replaces a short URL's editable fields wholesale (short_code,
// domain_id, created_by and status are not editable here — status changes
// go through Disable, which is a separate, more restrictive permission).
type UpdateInput struct {
	LongURL     string
	Title       string
	Description string
	ExpiresAt   *time.Time
}

// ListPage bounds how many rows List/ListAll return in one call, so an
// admin's "list every short URL" can't return an unbounded result set.
type ListPage struct {
	Limit  int
	Offset int
}

func (p ListPage) normalize() ListPage {
	if p.Limit <= 0 || p.Limit > 200 {
		p.Limit = 50
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	return p
}

// Store is the persistence port Service depends on.
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

	// ListForUser returns short URLs userID holds any url_permissions
	// grant on (自身が作成/招待された短縮URLの管理のみ、4.1節), newest first.
	ListForUser(ctx context.Context, userID uuid.UUID, page ListPage) ([]*ShortURL, error)

	// ListAll returns every short URL, newest first — for system_admin's
	// unrestricted view (4.1節).
	ListAll(ctx context.Context, page ListPage) ([]*ShortURL, error)

	// UpdateFields replaces long_url/title/description/expires_at.
	// Returns ErrNotFound if id doesn't exist.
	UpdateFields(ctx context.Context, id uuid.UUID, in UpdateInput) (*ShortURL, error)

	// SetStatus changes only status (used by Disable). Returns ErrNotFound
	// if id doesn't exist.
	SetStatus(ctx context.Context, id uuid.UUID, status Status) error
}

type Service struct {
	Store Store
	// RandomCode generates one candidate code from a charset/length pair;
	// defaults to a crypto/rand-backed generator. Override in tests for a
	// deterministic sequence.
	RandomCode func(charset string, length int) (string, error)
}

func (c *Service) randomCode(charset string, length int) (string, error) {
	if c.RandomCode != nil {
		return c.RandomCode(charset, length)
	}
	return randomCode(charset, length)
}

// Create validates the long URL and either uses the caller's custom alias
// or generates a random short_code per short_code_settings, retrying on
// collision.
func (c *Service) Create(ctx context.Context, in CreateInput) (*ShortURL, error) {
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

func (c *Service) insert(ctx context.Context, in CreateInput, longURL, code string) (*ShortURL, error) {
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

// ListForUser returns the short URLs userID holds any grant on.
func (c *Service) ListForUser(ctx context.Context, userID uuid.UUID, page ListPage) ([]*ShortURL, error) {
	return c.Store.ListForUser(ctx, userID, page.normalize())
}

// ListAll returns every short URL — callers must have already established
// the caller is a system_admin (4.1節); Service does not re-check authorization.
func (c *Service) ListAll(ctx context.Context, page ListPage) ([]*ShortURL, error) {
	return c.Store.ListAll(ctx, page.normalize())
}

// Update replaces long_url/title/description/expires_at. Callers must have
// already checked permission.Access.CanEdit; Service does not re-check
// authorization.
func (c *Service) Update(ctx context.Context, id uuid.UUID, in UpdateInput) (*ShortURL, error) {
	longURL, err := normalizeLongURL(in.LongURL)
	if err != nil {
		return nil, err
	}
	return c.Store.UpdateFields(ctx, id, UpdateInput{
		LongURL:     longURL,
		Title:       in.Title,
		Description: in.Description,
		ExpiresAt:   in.ExpiresAt,
	})
}

// Disable deactivates a short URL (status=disabled) instead of hard-deleting
// it: click_events retains an indefinite history (10節・2.2節) and
// references short_urls without ON DELETE CASCADE, so an actual DELETE
// would either fail once the URL has any recorded clicks or silently
// destroy that history — neither matches the confirmed retention policy.
// This is what the "URL削除" permission (4.2節, owner-only) maps to.
func (c *Service) Disable(ctx context.Context, id uuid.UUID) error {
	return c.Store.SetStatus(ctx, id, StatusDisabled)
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
