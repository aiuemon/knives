package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aiuemon/knives/internal/auth"
	"github.com/aiuemon/knives/internal/storage"
)

type fakeUserResolver struct {
	byEmail map[string]*auth.User
	created []string
}

func newFakeUserResolver() *fakeUserResolver {
	return &fakeUserResolver{byEmail: map[string]*auth.User{}}
}

func (r *fakeUserResolver) FindUserByEmail(_ context.Context, email string) (*auth.User, error) {
	if u, ok := r.byEmail[normalizeEmail(email)]; ok {
		return u, nil
	}
	return nil, auth.ErrNotFound
}

func (r *fakeUserResolver) CreateUser(_ context.Context, email string, emailVerified bool) (*auth.User, error) {
	u := &auth.User{ID: uuid.New(), Email: email, EmailVerified: emailVerified}
	r.byEmail[normalizeEmail(email)] = u
	r.created = append(r.created, email)
	return u, nil
}

type grantedRecord struct {
	shortURLID, userID, grantedBy uuid.UUID
}

type statsRecord struct {
	shortURLID uuid.UUID
	date       time.Time
	total      int64
}

type fakeMigrationTarget struct {
	existingShortCodes map[string]bool
	inserted           []storage.MigratedShortURLInput
	grants             []grantedRecord
	stats              []statsRecord
	grantErrForCode    map[string]error
}

func newFakeMigrationTarget() *fakeMigrationTarget {
	return &fakeMigrationTarget{
		existingShortCodes: map[string]bool{},
		grantErrForCode:    map[string]error{},
	}
}

func (t *fakeMigrationTarget) InsertMigratedShortURL(_ context.Context, in storage.MigratedShortURLInput) (uuid.UUID, error) {
	if t.existingShortCodes[in.ShortCode] {
		return uuid.Nil, storage.ErrMigratedShortURLAlreadyExists
	}
	t.existingShortCodes[in.ShortCode] = true
	t.inserted = append(t.inserted, in)
	// テストから参照しやすいよう、決定的なIDにする代わりにinsert順で新規生成する。
	id := uuid.New()
	return id, nil
}

func (t *fakeMigrationTarget) GrantOwner(_ context.Context, shortURLID, userID, grantedBy uuid.UUID) error {
	t.grants = append(t.grants, grantedRecord{shortURLID, userID, grantedBy})
	return nil
}

func (t *fakeMigrationTarget) SetClickStatsTotal(_ context.Context, shortURLID uuid.UUID, date time.Time, total int64) error {
	t.stats = append(t.stats, statsRecord{shortURLID, date, total})
	return nil
}

func TestRunMigration_CreatesSystemUserAndAppliesOwnerMapping(t *testing.T) {
	users := newFakeUserResolver()
	target := newFakeMigrationTarget()
	domainID := uuid.New()

	rows := []yourlsRow{
		{Keyword: "mapped", URL: "https://example.com/a", CreatedAt: time.Now(), Clicks: 5},
		{Keyword: "unmapped", URL: "https://example.com/b", CreatedAt: time.Now(), Clicks: 0},
	}
	owners := map[string]string{"mapped": "owner@example.com"}

	s, err := runMigration(context.Background(), users, target, domainID, "system@example.com", rows, owners)
	if err != nil {
		t.Fatalf("runMigration: %v", err)
	}
	if s.Migrated != 2 || s.Skipped != 0 || s.Failed != 0 {
		t.Fatalf("unexpected summary: %+v", s)
	}
	if len(target.inserted) != 2 || target.inserted[0].CreatedBy != users.byEmail["system@example.com"].ID {
		t.Fatalf("expected created_by to always be the system user, got %+v", target.inserted)
	}

	systemID := users.byEmail["system@example.com"].ID
	ownerID := users.byEmail["owner@example.com"].ID
	if ownerID == uuid.Nil {
		t.Fatalf("expected owner@example.com to have been created")
	}
	if target.grants[0].userID != ownerID || target.grants[0].grantedBy != systemID {
		t.Fatalf("expected the mapped row's owner to be owner@example.com, got %+v", target.grants[0])
	}
	if target.grants[1].userID != systemID {
		t.Fatalf("expected the unmapped row to fall back to the system user as owner, got %+v", target.grants[1])
	}
}

func TestRunMigration_SkipsRowsWithAlreadyExistingShortCode(t *testing.T) {
	users := newFakeUserResolver()
	target := newFakeMigrationTarget()
	target.existingShortCodes["already-there"] = true

	rows := []yourlsRow{
		{Keyword: "already-there", URL: "https://example.com/a", CreatedAt: time.Now()},
		{Keyword: "new-one", URL: "https://example.com/b", CreatedAt: time.Now()},
	}

	s, err := runMigration(context.Background(), users, target, uuid.New(), "system@example.com", rows, nil)
	if err != nil {
		t.Fatalf("runMigration: %v", err)
	}
	if s.Migrated != 1 || s.Skipped != 1 || s.Failed != 0 {
		t.Fatalf("expected 1 migrated + 1 skipped (idempotent re-run), got %+v", s)
	}
}

func TestRunMigration_OnlySetsClickStatsWhenClicksIsPositive(t *testing.T) {
	users := newFakeUserResolver()
	target := newFakeMigrationTarget()

	rows := []yourlsRow{
		{Keyword: "no-clicks", URL: "https://example.com/a", CreatedAt: time.Now(), Clicks: 0},
		{Keyword: "has-clicks", URL: "https://example.com/b", CreatedAt: time.Now(), Clicks: 10},
	}

	if _, err := runMigration(context.Background(), users, target, uuid.New(), "system@example.com", rows, nil); err != nil {
		t.Fatalf("runMigration: %v", err)
	}
	if len(target.stats) != 1 || target.stats[0].total != 10 {
		t.Fatalf("expected exactly one click-stats write for the row with clicks>0, got %+v", target.stats)
	}
}

func TestRunMigration_ReusesAlreadyResolvedOwnerAcrossRows(t *testing.T) {
	users := newFakeUserResolver()
	target := newFakeMigrationTarget()

	rows := []yourlsRow{
		{Keyword: "row1", URL: "https://example.com/a", CreatedAt: time.Now()},
		{Keyword: "row2", URL: "https://example.com/b", CreatedAt: time.Now()},
	}
	owners := map[string]string{"row1": "shared-owner@example.com", "row2": "shared-owner@example.com"}

	if _, err := runMigration(context.Background(), users, target, uuid.New(), "system@example.com", rows, owners); err != nil {
		t.Fatalf("runMigration: %v", err)
	}
	if len(users.created) != 2 { // system user + shared-owner, but not shared-owner twice
		t.Fatalf("expected the shared owner to be created only once (cached), got created=%v", users.created)
	}
}

type failingUserResolver struct{}

func (failingUserResolver) FindUserByEmail(context.Context, string) (*auth.User, error) {
	return nil, auth.ErrNotFound
}

func (failingUserResolver) CreateUser(context.Context, string, bool) (*auth.User, error) {
	return nil, errors.New("db unavailable")
}

func TestRunMigration_FailsFastIfTheSystemUserCannotBeResolved(t *testing.T) {
	_, err := runMigration(context.Background(), failingUserResolver{}, newFakeMigrationTarget(), uuid.New(), "system@example.com", nil, nil)
	if err == nil {
		t.Fatalf("expected an error when the system user itself can't be created")
	}
}
