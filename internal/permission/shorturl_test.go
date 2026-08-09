package permission

import (
	"testing"

	"github.com/google/uuid"
)

func TestResolve_OwnerHasFullAccess(t *testing.T) {
	subject := Subject{UserID: uuid.New()}
	grant := &Grant{UserID: subject.UserID, Role: RoleOwner}

	access := Resolve(subject, grant)

	if !access.Visible || !access.CanEdit || !access.CanManagePermissions || !access.CanDelete {
		t.Fatalf("owner should have full access, got %+v", access)
	}
	if access.AdminOverride {
		t.Fatalf("a real grant must never be reported as AdminOverride")
	}
}

func TestResolve_EditorCanViewAndEditOnly(t *testing.T) {
	subject := Subject{UserID: uuid.New()}
	grant := &Grant{UserID: subject.UserID, Role: RoleEditor}

	access := Resolve(subject, grant)

	if !access.Visible || !access.CanEdit {
		t.Fatalf("editor should be able to view and edit, got %+v", access)
	}
	if access.CanManagePermissions || access.CanDelete {
		t.Fatalf("editor must not manage permissions or delete, got %+v", access)
	}
}

func TestResolve_ViewerCanOnlyView(t *testing.T) {
	subject := Subject{UserID: uuid.New()}
	grant := &Grant{UserID: subject.UserID, Role: RoleViewer}

	access := Resolve(subject, grant)

	if !access.Visible {
		t.Fatalf("viewer should be able to view, got %+v", access)
	}
	if access.CanEdit || access.CanManagePermissions || access.CanDelete {
		t.Fatalf("viewer must not edit/manage/delete, got %+v", access)
	}
}

func TestResolve_NoGrantAndNotAdminIsInvisible(t *testing.T) {
	subject := Subject{UserID: uuid.New()}

	access := Resolve(subject, nil)

	if access != (Access{}) {
		t.Fatalf("expected a fully-zero Access (callers must respond 404), got %+v", access)
	}
}

func TestResolve_SystemAdminWithoutGrantCanViewOnly(t *testing.T) {
	subject := Subject{UserID: uuid.New(), IsSystemAdmin: true}

	access := Resolve(subject, nil)

	if !access.Visible || !access.AdminOverride {
		t.Fatalf("admin without a grant should see the URL via override, got %+v", access)
	}
	if access.CanEdit || access.CanManagePermissions || access.CanDelete {
		t.Fatalf("admin's unlimited access is view-only, not edit/manage/delete, got %+v", access)
	}
}

func TestResolve_SystemAdminWithOwnGrantUsesGrantNotOverride(t *testing.T) {
	subject := Subject{UserID: uuid.New(), IsSystemAdmin: true}
	grant := &Grant{UserID: subject.UserID, Role: RoleOwner}

	access := Resolve(subject, grant)

	if access.AdminOverride {
		t.Fatalf("an admin acting on their own owned URL must not be flagged as AdminOverride (no audit noise)")
	}
	if !access.CanDelete {
		t.Fatalf("admin's own owner grant should still grant full owner access, got %+v", access)
	}
}

func TestWouldOrphanOwnership(t *testing.T) {
	cases := []struct {
		name       string
		role       Role
		ownerCount int
		want       bool
	}{
		{"last owner revoked", RoleOwner, 1, true},
		{"one of several owners revoked", RoleOwner, 2, false},
		{"editor revoked never orphans ownership", RoleEditor, 1, false},
		{"viewer revoked never orphans ownership", RoleViewer, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := WouldOrphanOwnership(tc.role, tc.ownerCount); got != tc.want {
				t.Fatalf("WouldOrphanOwnership(%s, %d) = %v, want %v", tc.role, tc.ownerCount, got, tc.want)
			}
		})
	}
}
