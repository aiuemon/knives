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
	byID    map[uuid.UUID]ShortURL
	calls   int
}

func newFakeStore(charset string, length int) *fakeStore {
	return &fakeStore{charset: charset, length: length, taken: map[string]bool{}, byID: map[uuid.UUID]ShortURL{}}
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
	s.byID[in.ID] = in
	return &in, nil
}

func (s *fakeStore) FindByID(_ context.Context, id uuid.UUID) (*ShortURL, error) {
	su, ok := s.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &su, nil
}

func (s *fakeStore) ListForUser(_ context.Context, userID uuid.UUID, page ListPage) ([]*ListItem, int, error) {
	var result []*ListItem
	for _, su := range s.byID {
		if su.CreatedBy == userID {
			cp := su
			result = append(result, &ListItem{ShortURL: cp})
		}
	}
	return paginate(result, page), len(result), nil
}

func (s *fakeStore) ListAll(_ context.Context, page ListPage) ([]*ListItem, int, error) {
	var result []*ListItem
	for _, su := range s.byID {
		cp := su
		result = append(result, &ListItem{ShortURL: cp})
	}
	return paginate(result, page), len(result), nil
}

func paginate(all []*ListItem, page ListPage) []*ListItem {
	if page.Offset >= len(all) {
		return nil
	}
	end := page.Offset + page.Limit
	if end > len(all) {
		end = len(all)
	}
	return all[page.Offset:end]
}

func (s *fakeStore) UpdateFields(_ context.Context, id uuid.UUID, in UpdateInput) (*ShortURL, error) {
	su, ok := s.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	su.LongURL = in.LongURL
	su.Title = in.Title
	su.Description = in.Description
	su.ExpiresAt = in.ExpiresAt
	s.byID[id] = su
	return &su, nil
}

func (s *fakeStore) SetStatus(_ context.Context, id uuid.UUID, status Status) error {
	su, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	su.Status = status
	s.byID[id] = su
	return nil
}

func TestCreate_RandomCodeOnFirstAttempt(t *testing.T) {
	store := newFakeStore("abcdefghijklmnopqrstuvwxyz0123456789", 7)
	c := &Service{Store: store}

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
	c := &Service{
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

	c := &Service{
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
	c := &Service{Store: store}

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

	c := &Service{Store: store}
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
	c := &Service{Store: store}

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

func TestCreate_ReservedAliasRejectedWithoutStoreCall(t *testing.T) {
	// api/redirect/webを1つのFQDNに統合する構成では"/api/*"と"/app/*"が
	// cmd/api・webにルーティングされ、cmd/redirectには届かない
	// (deploy/nginx/nginx.conf)。そのためshort_codeとして"api"/"app"は
	// 使えないようにする。
	for _, alias := range []string{"api", "app"} {
		t.Run(alias, func(t *testing.T) {
			store := newFakeStore("abc", 5)
			c := &Service{Store: store}

			_, err := c.Create(context.Background(), CreateInput{
				DomainID:    uuid.New(),
				CustomAlias: alias,
				LongURL:     "https://example.com",
				CreatedBy:   uuid.New(),
			})
			if !errors.Is(err, ErrInvalidAlias) {
				t.Fatalf("expected ErrInvalidAlias for reserved alias %q, got %v", alias, err)
			}
			if store.calls != 0 {
				t.Fatalf("a reserved alias must fail validation before touching the store, got %d calls", store.calls)
			}
		})
	}
}

func TestCreate_RejectsNonHTTPLongURL(t *testing.T) {
	store := newFakeStore("abc", 5)
	c := &Service{Store: store}

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

func TestService_ListForUser_OnlyReturnsThatUsersURLs(t *testing.T) {
	store := newFakeStore("abc", 5)
	svc := &Service{Store: store}
	ctx := context.Background()

	userA := uuid.New()
	userB := uuid.New()
	if _, err := svc.Create(ctx, CreateInput{DomainID: uuid.New(), LongURL: "https://example.com/a", CreatedBy: userA}); err != nil {
		t.Fatalf("Create A: %v", err)
	}
	if _, err := svc.Create(ctx, CreateInput{DomainID: uuid.New(), LongURL: "https://example.com/b", CreatedBy: userB}); err != nil {
		t.Fatalf("Create B: %v", err)
	}

	listA, total, err := svc.ListForUser(ctx, userA, ListPage{})
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected total 1, got %d", total)
	}
	if len(listA) != 1 || listA[0].CreatedBy != userA {
		t.Fatalf("expected exactly userA's own URL, got %+v", listA)
	}
}

func TestService_ListAll_ReturnsEveryURL(t *testing.T) {
	store := newFakeStore("abc", 5)
	svc := &Service{Store: store}
	ctx := context.Background()

	if _, err := svc.Create(ctx, CreateInput{DomainID: uuid.New(), LongURL: "https://example.com/a", CreatedBy: uuid.New()}); err != nil {
		t.Fatalf("Create A: %v", err)
	}
	if _, err := svc.Create(ctx, CreateInput{DomainID: uuid.New(), LongURL: "https://example.com/b", CreatedBy: uuid.New()}); err != nil {
		t.Fatalf("Create B: %v", err)
	}

	all, total, err := svc.ListAll(ctx, ListPage{})
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if total != 2 {
		t.Fatalf("expected total 2, got %d", total)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 URLs, got %d", len(all))
	}
}

func TestService_Update_NormalizesLongURLAndReplacesFields(t *testing.T) {
	store := newFakeStore("abc", 5)
	svc := &Service{Store: store}
	ctx := context.Background()

	created, err := svc.Create(ctx, CreateInput{DomainID: uuid.New(), LongURL: "https://example.com/old", CreatedBy: uuid.New()})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	updated, err := svc.Update(ctx, created.ID, UpdateInput{LongURL: "https://example.com/new", Title: "new title"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.LongURL != "https://example.com/new" || updated.Title != "new title" {
		t.Fatalf("unexpected update result: %+v", updated)
	}
}

func TestService_Update_RejectsInvalidLongURL(t *testing.T) {
	store := newFakeStore("abc", 5)
	svc := &Service{Store: store}
	ctx := context.Background()

	created, err := svc.Create(ctx, CreateInput{DomainID: uuid.New(), LongURL: "https://example.com/old", CreatedBy: uuid.New()})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := svc.Update(ctx, created.ID, UpdateInput{LongURL: "javascript:alert(1)"}); !errors.Is(err, ErrInvalidLongURL) {
		t.Fatalf("expected ErrInvalidLongURL, got %v", err)
	}
	unchanged, _ := store.FindByID(ctx, created.ID)
	if unchanged.LongURL != "https://example.com/old" {
		t.Fatalf("a rejected update must not modify the stored URL, got %+v", unchanged)
	}
}

func TestService_Disable_SetsStatusToDisabled(t *testing.T) {
	store := newFakeStore("abc", 5)
	svc := &Service{Store: store}
	ctx := context.Background()

	created, err := svc.Create(ctx, CreateInput{DomainID: uuid.New(), LongURL: "https://example.com/old", CreatedBy: uuid.New()})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := svc.Disable(ctx, created.ID); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	after, _ := store.FindByID(ctx, created.ID)
	if after.Status != StatusDisabled {
		t.Fatalf("expected status disabled, got %q", after.Status)
	}
}
