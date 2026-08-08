import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

export function ProtectedRoute({ children }: { children: ReactNode }) {
	const { user, isLoading } = useAuth();

	if (isLoading) {
		return <p className="p-8 text-center text-gray-500">読み込み中…</p>;
	}
	if (!user) {
		return <Navigate to="/login" replace />;
	}
	return <>{children}</>;
}
