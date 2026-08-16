import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import type { PendingLink } from "../api/types";
import { useAuth } from "../auth/AuthContext";

export function Header() {
	const { user, clear } = useAuth();
	const navigate = useNavigate();

	// PendingLinksPageと同じqueryKeyを使うことで、承認操作後の
	// invalidateQueries(["pending-links"])がこのバッジにも自動で反映される。
	const pendingLinksQuery = useQuery({
		queryKey: ["pending-links"],
		queryFn: () => api.get<PendingLink[]>("/auth/pending-links"),
		enabled: !!user,
	});
	const pendingCount = pendingLinksQuery.data?.length ?? 0;

	async function handleLogout() {
		await api.post("/auth/logout");
		clear();
		navigate("/login");
	}

	return (
		<header className="flex items-center justify-between border-b border-gray-200 px-6 py-4 dark:border-gray-700">
			<Link to="/" className="text-lg font-semibold">
				knives
			</Link>
			{user && (
				<div className="flex items-center gap-4 text-sm">
					{pendingCount > 0 && (
						<Link
							to="/pending-links"
							className="flex items-center gap-1.5 text-gray-600 hover:underline dark:text-gray-300"
						>
							保留中の統合リクエスト
							<span className="inline-flex min-w-5 items-center justify-center rounded-full bg-indigo-600 px-1.5 py-0.5 text-xs font-medium text-white">
								{pendingCount}
							</span>
						</Link>
					)}
					<Link
						to="/account"
						className="text-gray-600 hover:underline dark:text-gray-300"
					>
						アカウント設定
					</Link>
					{user.is_system_admin && (
						<Link
							to="/admin/settings"
							className="text-gray-600 hover:underline dark:text-gray-300"
						>
							管理
						</Link>
					)}
					<span className="text-gray-500 dark:text-gray-400">{user.email}</span>
					<button
						type="button"
						onClick={handleLogout}
						className="rounded border border-gray-300 px-3 py-1 hover:bg-gray-50 dark:border-gray-600 dark:hover:bg-gray-800"
					>
						ログアウト
					</button>
				</div>
			)}
		</header>
	);
}
