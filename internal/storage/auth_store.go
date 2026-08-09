package storage

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/aiuemon/knives/internal/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// AuthStore adapts the sqlc-generated Queries to the auth.Store port that
// internal/auth's account-integration logic depends on.
type AuthStore struct {
	Q Querier
}

var _ auth.Store = (*AuthStore)(nil)

func NewAuthStore(db DBTX) *AuthStore {
	return &AuthStore{Q: New(db)}
}

func (s *AuthStore) FindAuthIdentity(ctx context.Context, providerType auth.ProviderType, providerConfigID *uuid.UUID, subject string) (*auth.AuthIdentity, error) {
	row, err := s.Q.FindAuthIdentity(ctx, FindAuthIdentityParams{
		ProviderType:     AuthProviderType(providerType),
		ProviderConfigID: toNullUUID(providerConfigID),
		Subject:          subject,
	})
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &auth.AuthIdentity{ID: row.ID, UserID: row.UserID, EmailAtLink: row.EmailAtLink}, nil
}

func (s *AuthStore) FindUserByEmail(ctx context.Context, email string) (*auth.User, error) {
	row, err := s.Q.FindUserByEmail(ctx, email)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &auth.User{ID: row.ID, Email: row.Email, EmailVerified: row.EmailVerified}, nil
}

func (s *AuthStore) FindUserByID(ctx context.Context, id uuid.UUID) (*auth.User, error) {
	row, err := s.Q.FindUserByID(ctx, id)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &auth.User{ID: row.ID, Email: row.Email, EmailVerified: row.EmailVerified}, nil
}

func (s *AuthStore) CountAuthIdentitiesForUser(ctx context.Context, userID uuid.UUID) (int, error) {
	count, err := s.Q.CountAuthIdentitiesForUser(ctx, userID)
	if err != nil {
		return 0, err
	}
	return int(count), nil
}

func (s *AuthStore) CreateUser(ctx context.Context, email string, emailVerified bool) (*auth.User, error) {
	row, err := s.Q.CreateUser(ctx, CreateUserParams{Email: email, EmailVerified: emailVerified})
	if err != nil {
		return nil, err
	}
	return &auth.User{ID: row.ID, Email: row.Email, EmailVerified: row.EmailVerified}, nil
}

func (s *AuthStore) CreateAuthIdentity(ctx context.Context, userID uuid.UUID, providerType auth.ProviderType, providerConfigID *uuid.UUID, subject, emailAtLink string, verified bool) (*auth.AuthIdentity, error) {
	row, err := s.Q.CreateAuthIdentity(ctx, CreateAuthIdentityParams{
		UserID:           userID,
		ProviderType:     AuthProviderType(providerType),
		ProviderConfigID: toNullUUID(providerConfigID),
		Subject:          subject,
		EmailAtLink:      emailAtLink,
		Verified:         verified,
	})
	if err != nil {
		return nil, err
	}
	return &auth.AuthIdentity{ID: row.ID, UserID: row.UserID, EmailAtLink: row.EmailAtLink}, nil
}

func (s *AuthStore) TouchAuthIdentity(ctx context.Context, id uuid.UUID, at time.Time) error {
	return s.Q.TouchAuthIdentity(ctx, TouchAuthIdentityParams{ID: id, LastUsedAt: toTimestamptz(at)})
}

func (s *AuthStore) CreatePendingLinkRequest(ctx context.Context, existingUserID uuid.UUID, providerType auth.ProviderType, providerConfigID *uuid.UUID, subject, tokenHash string, expiresAt time.Time) (uuid.UUID, error) {
	return s.Q.CreatePendingLinkRequest(ctx, CreatePendingLinkRequestParams{
		ExistingUserID:            existingUserID,
		CandidateProviderType:     AuthProviderType(providerType),
		CandidateProviderConfigID: toNullUUID(providerConfigID),
		CandidateSubject:          subject,
		TokenHash:                 tokenHash,
		ExpiresAt:                 toTimestamptz(expiresAt),
	})
}

func (s *AuthStore) FindPendingLinkRequestByTokenHash(ctx context.Context, tokenHash string) (*auth.PendingLinkRequest, error) {
	row, err := s.Q.FindPendingLinkRequestByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, mapNotFound(err)
	}
	var confirmedAt *time.Time
	if row.ConfirmedAt.Valid {
		t := row.ConfirmedAt.Time
		confirmedAt = &t
	}
	return &auth.PendingLinkRequest{
		ID:               row.ID,
		ExistingUserID:   row.ExistingUserID,
		ProviderType:     auth.ProviderType(row.CandidateProviderType),
		ProviderConfigID: fromNullUUID(row.CandidateProviderConfigID),
		Subject:          row.CandidateSubject,
		ExpiresAt:        row.ExpiresAt.Time,
		ConfirmedAt:      confirmedAt,
	}, nil
}

func (s *AuthStore) FindPendingLinkRequestByID(ctx context.Context, id uuid.UUID) (*auth.PendingLinkRequest, error) {
	row, err := s.Q.FindPendingLinkRequestByID(ctx, id)
	if err != nil {
		return nil, mapNotFound(err)
	}
	var confirmedAt *time.Time
	if row.ConfirmedAt.Valid {
		t := row.ConfirmedAt.Time
		confirmedAt = &t
	}
	return &auth.PendingLinkRequest{
		ID:               row.ID,
		ExistingUserID:   row.ExistingUserID,
		ProviderType:     auth.ProviderType(row.CandidateProviderType),
		ProviderConfigID: fromNullUUID(row.CandidateProviderConfigID),
		Subject:          row.CandidateSubject,
		ExpiresAt:        row.ExpiresAt.Time,
		ConfirmedAt:      confirmedAt,
	}, nil
}

func (s *AuthStore) FindPendingLinkRequestsForUser(ctx context.Context, userID uuid.UUID) ([]*auth.PendingLinkRequest, error) {
	rows, err := s.Q.FindPendingLinkRequestsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]*auth.PendingLinkRequest, 0, len(rows))
	for _, row := range rows {
		result = append(result, &auth.PendingLinkRequest{
			ID:               row.ID,
			ExistingUserID:   row.ExistingUserID,
			ProviderType:     auth.ProviderType(row.CandidateProviderType),
			ProviderConfigID: fromNullUUID(row.CandidateProviderConfigID),
			Subject:          row.CandidateSubject,
			ExpiresAt:        row.ExpiresAt.Time,
			ConfirmedAt:      nil, // クエリでconfirmed_at IS NULLに絞っているため常にnil
		})
	}
	return result, nil
}

func (s *AuthStore) ConfirmPendingLinkRequest(ctx context.Context, id uuid.UUID, at time.Time) error {
	return s.Q.ConfirmPendingLinkRequest(ctx, ConfirmPendingLinkRequestParams{ID: id, ConfirmedAt: toTimestamptz(at)})
}

func (s *AuthStore) ListUsers(ctx context.Context, limit, offset int) ([]*auth.AdminUser, error) {
	rows, err := s.Q.ListUsers(ctx, ListUsersParams{Limit: int32(limit), Offset: int32(offset)})
	if err != nil {
		return nil, err
	}
	result := make([]*auth.AdminUser, 0, len(rows))
	for _, row := range rows {
		result = append(result, &auth.AdminUser{
			ID:            row.ID,
			Email:         row.Email,
			EmailVerified: row.EmailVerified,
			IsSystemAdmin: row.IsSystemAdmin,
			Status:        auth.UserStatus(row.Status),
			CreatedAt:     row.CreatedAt.Time,
		})
	}
	return result, nil
}

func (s *AuthStore) FindAdminUserByID(ctx context.Context, id uuid.UUID) (*auth.AdminUser, error) {
	row, err := s.Q.FindAdminUserByID(ctx, id)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &auth.AdminUser{
		ID:            row.ID,
		Email:         row.Email,
		EmailVerified: row.EmailVerified,
		IsSystemAdmin: row.IsSystemAdmin,
		Status:        auth.UserStatus(row.Status),
		CreatedAt:     row.CreatedAt.Time,
	}, nil
}

func (s *AuthStore) SetSystemAdmin(ctx context.Context, userID uuid.UUID, isAdmin bool) error {
	rowsAffected, err := s.Q.SetSystemAdmin(ctx, SetSystemAdminParams{ID: userID, IsSystemAdmin: isAdmin})
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return auth.ErrNotFound
	}
	return nil
}

func (s *AuthStore) SetUserStatus(ctx context.Context, userID uuid.UUID, status auth.UserStatus) error {
	rowsAffected, err := s.Q.SetUserStatus(ctx, SetUserStatusParams{ID: userID, Status: UserStatus(status)})
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return auth.ErrNotFound
	}
	return nil
}

func (s *AuthStore) RecordAuditLog(ctx context.Context, entry auth.AuditLogEntry) error {
	metadata, err := json.Marshal(entry.Metadata)
	if err != nil {
		return err
	}
	return s.Q.RecordAuditLog(ctx, RecordAuditLogParams{
		ActorUserID: toNullUUID(entry.ActorUserID),
		Action:      entry.Action,
		TargetType:  pgtype.Text{String: entry.TargetType, Valid: entry.TargetType != ""},
		TargetID:    pgtype.Text{String: entry.TargetID, Valid: entry.TargetID != ""},
		Metadata:    metadata,
	})
}

func mapNotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.ErrNotFound
	}
	return err
}

func toNullUUID(id *uuid.UUID) uuid.NullUUID {
	if id == nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: *id, Valid: true}
}

func fromNullUUID(n uuid.NullUUID) *uuid.UUID {
	if !n.Valid {
		return nil
	}
	id := n.UUID
	return &id
}

func toTimestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}
