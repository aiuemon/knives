import {
	type UseQueryResult,
	useQuery,
	useQueryClient,
} from "@tanstack/react-query";
import { createContext, type ReactNode, useContext } from "react";
import { ApiError, api } from "../api/client";
import type { User } from "../api/types";

interface AuthContextValue {
	user: User | null;
	isLoading: boolean;
	refetch: UseQueryResult["refetch"];
	clear: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

async function fetchMe(): Promise<User | null> {
	try {
		return await api.get<User>("/auth/me");
	} catch (err) {
		if (err instanceof ApiError && err.status === 401) {
			return null;
		}
		throw err;
	}
}

export function AuthProvider({ children }: { children: ReactNode }) {
	const queryClient = useQueryClient();
	const query = useQuery({ queryKey: ["me"], queryFn: fetchMe, retry: false });

	const value: AuthContextValue = {
		user: query.data ?? null,
		isLoading: query.isLoading,
		refetch: query.refetch,
		clear: () => queryClient.setQueryData(["me"], null),
	};

	return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
	const ctx = useContext(AuthContext);
	if (!ctx) {
		throw new Error("useAuth must be used within AuthProvider");
	}
	return ctx;
}
