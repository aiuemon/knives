package permission

import "github.com/google/uuid"

type Role string

const (
	RoleOwner  Role = "owner"
	RoleEditor Role = "editor"
	RoleViewer Role = "viewer"
)

// Grant is the acting subject's own url_permissions row for one short URL.
// Other users' grants on the same URL are irrelevant to this subject's
// access and are intentionally not modeled here.
type Grant struct {
	UserID uuid.UUID
	Role   Role
}

// Subject is the acting principal for a permission check.
type Subject struct {
	UserID        uuid.UUID
	IsSystemAdmin bool
}

// Access describes what a subject may do on one short URL (4.2節).
type Access struct {
	// Visible gates every response about this URL, including its existence.
	// When false, callers must respond 404 — never 403 — so unauthorized
	// users cannot learn the URL exists at all (4.2節).
	Visible              bool
	CanEdit              bool
	CanManagePermissions bool
	CanDelete            bool
	// AdminOverride is true when Visible was granted purely by
	// system_admin status rather than an actual url_permissions grant.
	// Callers MUST record an audit_log "stats.admin_view" entry whenever
	// AdminOverride is true and the URL (details or stats) is actually
	// accessed, to keep the unlimited admin view auditable (4.1節).
	AdminOverride bool
}

// Resolve computes what subject may do on a short URL given the subject's
// own grant for it (nil if they have none).
func Resolve(subject Subject, grant *Grant) Access {
	if grant != nil {
		return accessForRole(grant.Role)
	}
	if subject.IsSystemAdmin {
		// 4.1節: 全短縮URLの閲覧(統計含む)は無制限。編集・権限管理・削除は
		// 「一般ユーザとしての短縮URL操作」に限られるため、実際のgrantが
		// ない他者URLには付与しない。
		return Access{Visible: true, AdminOverride: true}
	}
	return Access{}
}

func accessForRole(role Role) Access {
	switch role {
	case RoleOwner:
		return Access{Visible: true, CanEdit: true, CanManagePermissions: true, CanDelete: true}
	case RoleEditor:
		return Access{Visible: true, CanEdit: true}
	case RoleViewer:
		return Access{Visible: true}
	default:
		return Access{}
	}
}
