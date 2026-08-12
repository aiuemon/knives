import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, api } from "../api/client";
import type { AdminUser } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { Header } from "../components/Header";

export function AdminUsersPage() {
	const { user: me } = useAuth();
	const queryClient = useQueryClient();
	const [error, setError] = useState<string | null>(null);
	const [pendingId, setPendingId] = useState<string | null>(null);

	const query = useQuery({
		queryKey: ["admin", "users"],
		queryFn: () => api.get<AdminUser[]>("/admin/users"),
	});

	async function patchUser(id: string, body: Record<string, unknown>) {
		setError(null);
		setPendingId(id);
		try {
			const updated = await api.patch<AdminUser>(`/admin/users/${id}`, body);
			queryClient.setQueryData<AdminUser[]>(["admin", "users"], (current) =>
				current?.map((u) => (u.id === id ? updated : u)),
			);
		} catch (err) {
			setError(err instanceof ApiError ? err.message : "更新に失敗しました");
		} finally {
			setPendingId(null);
		}
	}

	// チェックボックスクリック一つで即座に権限が変わると誤操作の懸念が
	// あるため、確認ダイアログを挟んでから実際の変更を行う。キャンセル時は
	// 何もせず、checked は u.is_system_admin/u.status 由来のままなので
	// 見た目も自動的に元に戻る。
	function handleToggleAdmin(u: AdminUser) {
		const next = !u.is_system_admin;
		const message = next
			? `${u.email} に管理者権限を付与しますか?`
			: `${u.email} の管理者権限を剥奪しますか?`;
		if (!window.confirm(message)) {
			return;
		}
		patchUser(u.id, { is_system_admin: next });
	}

	function handleToggleDisabled(u: AdminUser) {
		const next = u.status === "suspended" ? "active" : "suspended";
		const message =
			next === "suspended"
				? `${u.email} を無効化しますか?`
				: `${u.email} を有効化しますか?`;
		if (!window.confirm(message)) {
			return;
		}
		patchUser(u.id, { status: next });
	}

	return (
		<div>
			<Header />
			<div className="mx-auto max-w-4xl px-4 py-8">
				<h1 className="mb-2 text-2xl font-semibold">ユーザー管理</h1>
				<nav className="mb-6 flex gap-4 text-sm">
					<Link
						to="/admin/settings"
						className="text-gray-600 hover:underline dark:text-gray-300"
					>
						認証設定
					</Link>
					<span className="font-medium text-indigo-600">ユーザー管理</span>
					<Link
						to="/admin/saml"
						className="text-gray-600 hover:underline dark:text-gray-300"
					>
						SAML設定
					</Link>
					<Link
						to="/admin/oidc"
						className="text-gray-600 hover:underline dark:text-gray-300"
					>
						OIDC設定
					</Link>
				</nav>
				{query.isLoading && <p>読み込み中…</p>}
				{query.isError && (
					<p className="text-sm text-red-600">
						ユーザー一覧の取得に失敗しました
					</p>
				)}
				{error && <p className="mb-4 text-sm text-red-600">{error}</p>}
				{query.data && (
					<div className="overflow-x-auto">
						<table className="w-full text-left text-sm">
							<thead>
								<tr className="border-b border-gray-200 text-gray-500 dark:border-gray-700 dark:text-gray-400">
									<th className="py-2 pr-4 font-medium">メールアドレス</th>
									<th className="py-2 pr-4 font-medium">管理者</th>
									<th className="py-2 pr-4 font-medium">無効</th>
									<th className="py-2 pr-4 font-medium">登録日</th>
								</tr>
							</thead>
							<tbody>
								{query.data.map((u) => {
									const isSelf = u.id === me?.id;
									const busy = pendingId === u.id;
									return (
										<tr
											key={u.id}
											className="border-b border-gray-100 dark:border-gray-800"
										>
											<td className="py-2 pr-4">{u.email}</td>
											<td className="py-2 pr-4">
												<input
													type="checkbox"
													checked={u.is_system_admin}
													disabled={busy || (isSelf && u.is_system_admin)}
													onChange={() => handleToggleAdmin(u)}
													aria-label="管理者"
													title={
														isSelf && u.is_system_admin
															? "自分自身のsystem_admin権限は剥奪できません"
															: undefined
													}
													className="h-4 w-4 disabled:opacity-50"
												/>
											</td>
											<td className="py-2 pr-4">
												<input
													type="checkbox"
													checked={u.status === "suspended"}
													disabled={busy || (isSelf && u.status === "active")}
													onChange={() => handleToggleDisabled(u)}
													aria-label="無効"
													title={
														isSelf && u.status === "active"
															? "自分自身のアカウントは無効化できません"
															: undefined
													}
													className="h-4 w-4 disabled:opacity-50"
												/>
											</td>
											<td className="py-2 pr-4 text-gray-500">
												{new Date(u.created_at).toLocaleDateString()}
											</td>
										</tr>
									);
								})}
							</tbody>
						</table>
					</div>
				)}
			</div>
		</div>
	);
}
