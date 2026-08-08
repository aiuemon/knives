import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthContext";

export function Header() {
	const { user, clear } = useAuth();
	const navigate = useNavigate();

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
					<Link
						to="/pending-links"
						className="text-gray-600 hover:underline dark:text-gray-300"
					>
						保留中の統合リクエスト
					</Link>
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
