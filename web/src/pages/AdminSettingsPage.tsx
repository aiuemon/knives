import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, api } from "../api/client";
import type { AuthSettings } from "../api/types";
import { Header } from "../components/Header";

const SETTINGS_LABELS: Record<keyof AuthSettings, string> = {
	local_auth_enabled: "ローカル認証(メール+パスワード)を有効にする",
	self_signup_enabled: "セルフサインアップを許可する",
	require_email_confirmation_for_signup:
		"セルフサインアップ時にメール確認を必須にする",
	require_reauth_for_account_link:
		"アカウント統合の承認に既存ログイン方法での再認証を必須にする(安全側・推奨)",
};

export function AdminSettingsPage() {
	const queryClient = useQueryClient();
	const [error, setError] = useState<string | null>(null);
	const query = useQuery({
		queryKey: ["admin", "auth-settings"],
		queryFn: () => api.get<AuthSettings>("/admin/auth-settings"),
	});

	async function handleToggle(key: keyof AuthSettings, next: boolean) {
		setError(null);
		try {
			const updated = await api.patch<AuthSettings>("/admin/auth-settings", {
				[key]: next,
			});
			queryClient.setQueryData(["admin", "auth-settings"], updated);
		} catch (err) {
			setError(err instanceof ApiError ? err.message : "更新に失敗しました");
		}
	}

	return (
		<div>
			<Header />
			<div className="mx-auto max-w-2xl px-4 py-8">
				<h1 className="mb-2 text-2xl font-semibold">システム設定</h1>
				<nav className="mb-6 flex gap-4 text-sm">
					<span className="font-medium text-indigo-600">認証設定</span>
					<Link
						to="/admin/users"
						className="text-gray-600 hover:underline dark:text-gray-300"
					>
						ユーザー管理
					</Link>
				</nav>
				{query.isLoading && <p>読み込み中…</p>}
				{query.isError && (
					<p className="text-sm text-red-600">設定の取得に失敗しました</p>
				)}
				{error && <p className="mb-4 text-sm text-red-600">{error}</p>}
				{query.data && (
					<ul className="flex flex-col gap-4">
						{(Object.keys(SETTINGS_LABELS) as (keyof AuthSettings)[]).map(
							(key) => (
								<li key={key}>
									<label className="flex items-start gap-3">
										<input
											type="checkbox"
											checked={query.data[key]}
											onChange={(e) => handleToggle(key, e.target.checked)}
											className="mt-1"
										/>
										<span className="text-sm">{SETTINGS_LABELS[key]}</span>
									</label>
								</li>
							),
						)}
					</ul>
				)}
			</div>
		</div>
	);
}
