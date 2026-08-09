package storage

import (
	"context"
	"errors"
	"time"

	"github.com/aiuemon/knives/internal/permission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// GrantWithEmail is one row of a short URL's permission list, joined with
// the grantee's email for display purposes.
type GrantWithEmail struct {
	UserID    uuid.UUID
	Email     string
	Role      permission.Role
	GrantedAt time.Time
}

// PermissionStore looks up a subject's own url_permissions grant for
// internal/permission's access decisions.
type PermissionStore struct {
	Q Querier
}

func NewPermissionStore(db DBTX) *PermissionStore {
	return &PermissionStore{Q: New(db)}
}

// FindGrant returns userID's own grant for shortURLID, or nil if they have
// none. A missing grant is not an error: permission.Resolve treats a nil
// Grant as "no access" and, combined with a non-admin subject, as
// invisible (4.2節: 403ではなく404を返す).
func (s *PermissionStore) FindGrant(ctx context.Context, shortURLID, userID uuid.UUID) (*permission.Grant, error) {
	role, err := s.Q.FindURLPermission(ctx, FindURLPermissionParams{ShortUrlID: shortURLID, UserID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &permission.Grant{UserID: userID, Role: permission.Role(role)}, nil
}

// IsSystemAdmin reports users.is_system_admin for userID, needed to build
// a permission.Subject.
func (s *PermissionStore) IsSystemAdmin(ctx context.Context, userID uuid.UUID) (bool, error) {
	return s.Q.FindIsSystemAdmin(ctx, userID)
}

// ListGrants returns everyone with access to shortURLID, oldest grant
// first.
func (s *PermissionStore) ListGrants(ctx context.Context, shortURLID uuid.UUID) ([]GrantWithEmail, error) {
	rows, err := s.Q.ListURLPermissions(ctx, shortURLID)
	if err != nil {
		return nil, err
	}
	result := make([]GrantWithEmail, 0, len(rows))
	for _, row := range rows {
		result = append(result, GrantWithEmail{
			UserID:    row.UserID,
			Email:     row.Email,
			Role:      permission.Role(row.Role),
			GrantedAt: row.GrantedAt.Time,
		})
	}
	return result, nil
}

// CountOwners reports how many owner grants shortURLID currently has —
// used to refuse a revoke/downgrade that would leave it with none (4.2節:
// a short URL must always have at least one owner).
func (s *PermissionStore) CountOwners(ctx context.Context, shortURLID uuid.UUID) (int, error) {
	count, err := s.Q.CountURLOwners(ctx, shortURLID)
	if err != nil {
		return 0, err
	}
	return int(count), nil
}

// Grant creates or updates userID's role on shortURLID.
func (s *PermissionStore) Grant(ctx context.Context, shortURLID, userID uuid.UUID, role permission.Role, grantedBy uuid.UUID) error {
	return s.Q.UpsertURLPermission(ctx, UpsertURLPermissionParams{
		ShortUrlID: shortURLID,
		UserID:     userID,
		Role:       UrlPermissionRole(role),
		GrantedBy:  grantedBy,
	})
}

// Revoke removes userID's access to shortURLID entirely.
func (s *PermissionStore) Revoke(ctx context.Context, shortURLID, userID uuid.UUID) error {
	return s.Q.DeleteURLPermission(ctx, DeleteURLPermissionParams{ShortUrlID: shortURLID, UserID: userID})
}
