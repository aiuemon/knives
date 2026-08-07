package shorturl

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

type fakeStore struct {
	charset string
	length  int
	taken   map[string]bool
	calls   int
}

func newFakeStore(charset string, length int) *fakeStore {
	return &fakeStore{charset: charset, length: length, taken: map[string]bool{}}
}

func (s *fakeStore) ShortCodeSettings(_ context.Context) (string, int, error) {
	return s.charset, s.length, nil
}

func (s *fakeStore) CreateShortURL(_ context.Context, in ShortURL) (*ShortURL, error) {
	s.calls++
	key := in.DomainID.String() + ":" + in.ShortCode
	if s.taken[key] {
		return nil, ErrCodeCollision
	}
	s.taken[key] = true
	in.ID = uuid.New()
	return &in, nil
}

func TestCreate_RandomCodeOnFirstAttempt(t *testing.T) {
	store := newFakeStore("abcdefghijklmnopqrstuvwxyz0123456789", 7)
	c := &Creator{Store: store}

	su, err := c.Create(context.Background(), CreateInput{
		DomainID:  uuid.New(),
		LongURL:   "https://example.com/very/long/path",
		CreatedBy: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(su.ShortCode) != 7 {
		t.Fatalf("expected a 7-character code, got %q", su.ShortCode)
	}
	if su.Status != StatusActive || su.Source != SourceNative {
		t.Fatalf("unexpected status/source: %+v", su)
	}
	if store.calls != 1 {
		t.Fatalf("expected exactly one Store call, got %d", store.calls)
	}
}

func TestCreate_RandomCodeRetriesOnCollision(t *testing.T) {
	store := newFakeStore("unused-real-charset", 3)
	domainID := uuid.New()
	store.taken[domainID.String()+":first"] = true

	// crypto/randの実際の出目に依存せず衝突→再試行を確定的に踏むため、
	// RandomCodeを注入してあらかじめ決めた系列を返させる。
	sequence := []string{"first", "second"}
	call := 0
	c := &Creator{
		Store: store,
		RandomCode: func(_ string, _ int) (string, error) {
			code := sequence[call]
			call++
			return code, nil
		},
	}

	su, err := c.Create(context.Background(), CreateInput{
		DomainID:  domainID,
		LongURL:   "https://example.com",
		CreatedBy: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if su.ShortCode != "second" {
		t.Fatalf("expected the retry to land on the second generated code, got %q", su.ShortCode)
	}
	if store.calls != 2 {
		t.Fatalf("expected a collision then a successful retry (2 store calls), got %d", store.calls)
	}
}

func TestCreate_RandomCodeExhaustsRetries(t *testing.T) {
	store := newFakeStore("unused-real-charset", 3)
	domainID := uuid.New()
	store.taken[domainID.String()+":always-taken"] = true

	c := &Creator{
		Store: store,
		RandomCode: func(_ string, _ int) (string, error) {
			return "always-taken", nil
		},
	}

	_, err := c.Create(context.Background(), CreateInput{
		DomainID:  domainID,
		LongURL:   "https://example.com",
		CreatedBy: uuid.New(),
	})
	if err == nil {
		t.Fatalf("expected an error when every random attempt collides")
	}
	if store.calls != maxRandomCodeAttempts {
		t.Fatalf("expected exactly %d attempts, got %d", maxRandomCodeAttempts, store.calls)
	}
}

func TestCreate_CustomAliasSuccess(t *testing.T) {
	store := newFakeStore("abc", 5)
	c := &Creator{Store: store}

	su, err := c.Create(context.Background(), CreateInput{
		DomainID:    uuid.New(),
		CustomAlias: "my-campaign_2026",
		LongURL:     "https://example.com/landing",
		CreatedBy:   uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if su.ShortCode != "my-campaign_2026" {
		t.Fatalf("expected the custom alias to be used verbatim, got %q", su.ShortCode)
	}
}

func TestCreate_CustomAliasCollisionReturnsErrAliasTaken(t *testing.T) {
	store := newFakeStore("abc", 5)
	domainID := uuid.New()
	store.taken[domainID.String()+":taken-alias"] = true

	c := &Creator{Store: store}
	_, err := c.Create(context.Background(), CreateInput{
		DomainID:    domainID,
		CustomAlias: "taken-alias",
		LongURL:     "https://example.com",
		CreatedBy:   uuid.New(),
	})
	if !errors.Is(err, ErrAliasTaken) {
		t.Fatalf("expected ErrAliasTaken, got %v", err)
	}
	if store.calls != 1 {
		t.Fatalf("a taken custom alias must not be retried with a different code, got %d calls", store.calls)
	}
}

func TestCreate_InvalidAliasRejectedWithoutStoreCall(t *testing.T) {
	store := newFakeStore("abc", 5)
	c := &Creator{Store: store}

	_, err := c.Create(context.Background(), CreateInput{
		DomainID:    uuid.New(),
		CustomAlias: "has a space",
		LongURL:     "https://example.com",
		CreatedBy:   uuid.New(),
	})
	if !errors.Is(err, ErrInvalidAlias) {
		t.Fatalf("expected ErrInvalidAlias, got %v", err)
	}
	if store.calls != 0 {
		t.Fatalf("an invalid alias must fail validation before touching the store, got %d calls", store.calls)
	}
}

func TestCreate_RejectsNonHTTPLongURL(t *testing.T) {
	store := newFakeStore("abc", 5)
	c := &Creator{Store: store}

	cases := []string{
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"not-a-url",
		"",
		"ftp://example.com/file",
	}
	for _, raw := range cases {
		_, err := c.Create(context.Background(), CreateInput{
			DomainID:  uuid.New(),
			LongURL:   raw,
			CreatedBy: uuid.New(),
		})
		if !errors.Is(err, ErrInvalidLongURL) {
			t.Fatalf("long_url %q: expected ErrInvalidLongURL, got %v", raw, err)
		}
	}
	if store.calls != 0 {
		t.Fatalf("an invalid long_url must fail validation before touching the store, got %d calls", store.calls)
	}
}

func TestRandomCode_UsesOnlyCharsetAndRequestedLength(t *testing.T) {
	const charset = "AB"
	code, err := randomCode(charset, 20)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(code) != 20 {
		t.Fatalf("expected length 20, got %d (%q)", len(code), code)
	}
	for _, r := range code {
		if r != 'A' && r != 'B' {
			t.Fatalf("code %q contains a character outside the charset %q", code, charset)
		}
	}
}

func TestRandomCode_RejectsEmptyCharsetOrNonPositiveLength(t *testing.T) {
	if _, err := randomCode("", 5); err == nil {
		t.Fatalf("expected an error for an empty charset")
	}
	if _, err := randomCode("abc", 0); err == nil {
		t.Fatalf("expected an error for a non-positive length")
	}
}
