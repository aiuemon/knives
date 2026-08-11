import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError, api } from "../api/client";
import type { ShortURL, URLPermissionGrant } from "../api/types";
import { Header } from "../components/Header";

const ROLE_LABELS: Record<string, string> = {
	owner: "オーナー",
	editor: "編集者",
	viewer: "閲覧者",
};

export function ShortURLPermissionsPage() {
	const { id } = useParams<{ id: string }>();
	const queryClient = useQueryClient();

	const [email, setEmail] = useState("");
	const [role, setRole] = useState("editor");
	const [error, setError] = useState<string | null>(null);
	const [inviting, setInviting] = useState(false);
	const [revokingUserId, setRevokingUserId] = useState<string | null>(null);

	const urlQuery = useQuery({
		queryKey: ["short-urls", id],
		queryFn: () => api.get<ShortURL>(`/short-urls/${id}`),
		enabled: !!id,
	});

	const grantsQuery = useQuery({
		queryKey: ["short-urls", id, "permissions"],
		queryFn: () =>
			api.get<URLPermissionGrant[]>(`/short-urls/${id}/permissions`),
		enabled: !!id && urlQuery.data?.can_manage_permissions === true,
	});

	async function handleInvite(e: FormEvent) {
		e.preventDefault();
		setError(null);
		setInviting(true);
		try {
			const grant = await api.post<URLPermissionGrant>(
				`/short-urls/${id}/permissions`,
				{ email, role },
			);
			queryClient.setQueryData<URLPermissionGrant[]>(
				["short-urls", id, "permissions"],
				(current) => (current ? [...current, grant] : [grant]),
			);
			setEmail("");
		} catch (err) {
			setError(err instanceof ApiError ? err.message : "招待に失敗しました");
		} finally {
			setInviting(false);
		}
	}

	async function handleRevoke(grant: URLPermissionGrant) {
		if (!window.confirm(`${grant.email} の権限を削除しますか?`)) {
			return;
		}
		setError(null);
		setRevokingUserId(grant.user_id);
		try {
			await api.delete(`/short-urls/${id}/permissions/${grant.user_id}`);
			queryClient.setQueryData<URLPermissionGrant[]>(
				["short-urls", id, "permissions"],
				(current) => current?.filter((g) => g.user_id !== grant.user_id),
			);
		} catch (err) {
			setError(
				err instanceof ApiError ? err.message : "権限の削除に失敗しました",
			);
		} finally {
			setRevokingUserId(null);
		}
	}

	return (
		<div>
			<Header />
			<div className="mx-auto max-w-2xl px-4 py-8">
				<Link
					to="/"
					className="mb-4 inline-block text-sm text-indigo-600 hover:underline"
				>
					← 短縮URL一覧に戻る
				</Link>
				<h1 className="mb-2 text-2xl font-semibold">権限管理</h1>

				{urlQuery.isLoading && <p>読み込み中…</p>}
				{urlQuery.isError && (
					<p className="text-sm text-red-600">短縮URLの取得に失敗しました</p>
				)}

				{urlQuery.data && (
					<p className="mb-6 truncate text-sm text-gray-500">
						{urlQuery.data.short_code} → {urlQuery.data.long_url}
					</p>
				)}

				{urlQuery.data && !urlQuery.data.can_manage_permissions && (
					<p className="rounded border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200">
						この短縮URLの権限管理はオーナーのみ行えます。
					</p>
				)}

				{urlQuery.data?.can_manage_permissions && (
					<>
						{error && <p className="mb-4 text-sm text-red-600">{error}</p>}

						<form
							onSubmit={handleInvite}
							className="mb-8 flex flex-col gap-4 rounded border border-gray-200 p-4 dark:border-gray-700"
						>
							<h2 className="text-lg font-medium">ユーザーを招待</h2>
							<label className="flex flex-col gap-1">
								<span className="text-sm text-gray-600 dark:text-gray-300">
									メールアドレス
								</span>
								<input
									type="email"
									required
									value={email}
									onChange={(e) => setEmail(e.target.value)}
									className="rounded border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800"
								/>
							</label>
							<label className="flex flex-col gap-1">
								<span className="text-sm text-gray-600 dark:text-gray-300">
									役割
								</span>
								<select
									value={role}
									onChange={(e) => setRole(e.target.value)}
									className="rounded border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800"
								>
									<option value="editor">編集者</option>
									<option value="viewer">閲覧者</option>
								</select>
							</label>
							<button
								type="submit"
								disabled={inviting}
								className="self-start rounded bg-indigo-600 px-4 py-2 text-white disabled:opacity-50"
							>
								{inviting ? "招待中…" : "招待"}
							</button>
						</form>

						<h2 className="mb-3 text-lg font-medium">権限を持つユーザー</h2>
						{grantsQuery.isLoading && <p>読み込み中…</p>}
						{grantsQuery.isError && (
							<p className="text-sm text-red-600">一覧の取得に失敗しました</p>
						)}
						<ul className="flex flex-col gap-2">
							{grantsQuery.data?.map((grant) => (
								<li
									key={grant.user_id}
									className="flex items-center justify-between rounded border border-gray-200 p-3 text-sm dark:border-gray-700"
								>
									<div>
										<p>{grant.email}</p>
										<p className="text-xs text-gray-500">
											{ROLE_LABELS[grant.role] ?? grant.role}
										</p>
									</div>
									<button
										type="button"
										disabled={revokingUserId === grant.user_id}
										onClick={() => handleRevoke(grant)}
										className="rounded border border-gray-300 px-2 py-1 text-xs disabled:opacity-50 dark:border-gray-600"
									>
										削除
									</button>
								</li>
							))}
						</ul>
					</>
				)}
			</div>
		</div>
	);
}
