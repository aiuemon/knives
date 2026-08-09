import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

// AdminRoute gates the /admin/* screens on is_system_admin. This is a UX
// convenience only — /api/admin/* itself is enforced server-side by
// requireSystemAdmin, so hiding the link here doesn't grant any access.
export function AdminRoute({ children }: { children: ReactNode }) {
	const { user, isLoading } = useAuth();

	if (isLoading) {
		return <p className="p-8 text-center text-gray-500">読み込み中…</p>;
	}
	if (!user) {
		return <Navigate to="/login" replace />;
	}
	if (!user.is_system_admin) {
		return <Navigate to="/" replace />;
	}
	return <>{children}</>;
}
