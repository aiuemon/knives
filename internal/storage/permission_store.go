package storage

import (
	"context"
	"errors"

	"github.com/aiuemon/knives/internal/permission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

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
