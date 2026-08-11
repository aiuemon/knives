import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, api } from "../api/client";
import type { ShortURL } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { Header } from "../components/Header";

const REDIRECT_BASE_URL =
	import.meta.env.VITE_REDIRECT_BASE_URL ?? "http://localhost:8081";

const ROLE_LABELS: Record<string, string> = {
	owner: "オーナー",
	editor: "編集者",
	viewer: "閲覧者",
};

type EditForm = {
	long_url: string;
	title: string;
	description: string;
};

const emptyEditForm: EditForm = { long_url: "", title: "", description: "" };

export function DashboardPage() {
	const { user } = useAuth();
	const queryClient = useQueryClient();

	const [longUrl, setLongUrl] = useState("");
	const [customAlias, setCustomAlias] = useState("");
	const [title, setTitle] = useState("");
	const [createError, setCreateError] = useState<string | null>(null);
	const [creating, setCreating] = useState(false);

	const [scopeMine, setScopeMine] = useState(false);
	const [editingId, setEditingId] = useState<string | null>(null);
	const [editForm, setEditForm] = useState<EditForm>(emptyEditForm);
	const [rowError, setRowError] = useState<string | null>(null);
	const [pendingId, setPendingId] = useState<string | null>(null);

	const showScopeToggle = user?.is_system_admin ?? false;
	const effectiveScopeMine = showScopeToggle ? scopeMine : true;

	const listQuery = useQuery({
		queryKey: ["short-urls", { mine: effectiveScopeMine }],
		queryFn: () =>
			api.get<ShortURL[]>(
				effectiveScopeMine ? "/short-urls?scope=mine" : "/short-urls",
			),
	});

	async function handleCreate(e: FormEvent) {
		e.preventDefault();
		setCreateError(null);
		setCreating(true);
		try {
			const su = await api.post<ShortURL>("/short-urls", {
				long_url: longUrl,
				custom_alias: customAlias || undefined,
				title: title || undefined,
			});
			queryClient.setQueryData<ShortURL[]>(
				["short-urls", { mine: effectiveScopeMine }],
				(current) => (current ? [su, ...current] : [su]),
			);
			setLongUrl("");
			setCustomAlias("");
			setTitle("");
		} catch (err) {
			setCreateError(
				err instanceof ApiError ? err.message : "作成に失敗しました",
			);
		} finally {
			setCreating(false);
		}
	}

	function startEdit(su: ShortURL) {
		setRowError(null);
		setEditingId(su.id);
		setEditForm({
			long_url: su.long_url,
			title: su.title ?? "",
			description: su.description ?? "",
		});
	}

	function cancelEdit() {
		setEditingId(null);
		setEditForm(emptyEditForm);
	}

	async function handleEditSubmit(e: FormEvent) {
		e.preventDefault();
		if (!editingId) {
			return;
		}
		setRowError(null);
		setPendingId(editingId);
		try {
			const updated = await api.patch<ShortURL>(
				`/short-urls/${editingId}`,
				editForm,
			);
			queryClient.setQueryData<ShortURL[]>(
				["short-urls", { mine: effectiveScopeMine }],
				(current) => current?.map((su) => (su.id === editingId ? updated : su)),
			);
			cancelEdit();
		} catch (err) {
			setRowError(err instanceof ApiError ? err.message : "更新に失敗しました");
		} finally {
			setPendingId(null);
		}
	}

	async function handleDelete(su: ShortURL) {
		if (!window.confirm(`「${su.short_code}」を削除しますか?`)) {
			return;
		}
		setRowError(null);
		setPendingId(su.id);
		try {
			await api.delete(`/short-urls/${su.id}`);
			queryClient.setQueryData<ShortURL[]>(
				["short-urls", { mine: effectiveScopeMine }],
				(current) => current?.filter((item) => item.id !== su.id),
			);
		} catch (err) {
			setRowError(err instanceof ApiError ? err.message : "削除に失敗しました");
		} finally {
			setPendingId(null);
		}
	}

	return (
		<div>
			<Header />
			<div className="mx-auto max-w-3xl px-4 py-8">
				<h1 className="mb-6 text-2xl font-semibold">短縮URLを作成</h1>
				<form onSubmit={handleCreate} className="mb-10 flex flex-col gap-4">
					<label className="flex flex-col gap-1">
						<span className="text-sm text-gray-600 dark:text-gray-300">
							遷移先URL
						</span>
						<input
							type="url"
							required
							placeholder="https://example.com/..."
							value={longUrl}
							onChange={(e) => setLongUrl(e.target.value)}
							className="rounded border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800"
						/>
					</label>
					<label className="flex flex-col gap-1">
						<span className="text-sm text-gray-600 dark:text-gray-300">
							カスタムエイリアス(任意)
						</span>
						<input
							type="text"
							value={customAlias}
							onChange={(e) => setCustomAlias(e.target.value)}
							placeholder="未指定ならランダム生成"
							className="rounded border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800"
						/>
					</label>
					<label className="flex flex-col gap-1">
						<span className="text-sm text-gray-600 dark:text-gray-300">
							タイトル(任意)
						</span>
						<input
							type="text"
							value={title}
							onChange={(e) => setTitle(e.target.value)}
							className="rounded border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800"
						/>
					</label>
					{createError && <p className="text-sm text-red-600">{createError}</p>}
					<button
						type="submit"
						disabled={creating}
						className="self-start rounded bg-indigo-600 px-4 py-2 text-white disabled:opacity-50"
					>
						{creating ? "作成中…" : "作成"}
					</button>
				</form>

				{editingId && (
					<form
						onSubmit={handleEditSubmit}
						className="mb-10 flex flex-col gap-4 rounded border border-gray-200 p-4 dark:border-gray-700"
					>
						<h2 className="text-lg font-medium">短縮URLを編集</h2>
						<label className="flex flex-col gap-1">
							<span className="text-sm text-gray-600 dark:text-gray-300">
								遷移先URL
							</span>
							<input
								type="url"
								required
								value={editForm.long_url}
								onChange={(e) =>
									setEditForm({ ...editForm, long_url: e.target.value })
								}
								className="rounded border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800"
							/>
						</label>
						<label className="flex flex-col gap-1">
							<span className="text-sm text-gray-600 dark:text-gray-300">
								タイトル(任意)
							</span>
							<input
								type="text"
								value={editForm.title}
								onChange={(e) =>
									setEditForm({ ...editForm, title: e.target.value })
								}
								className="rounded border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800"
							/>
						</label>
						<label className="flex flex-col gap-1">
							<span className="text-sm text-gray-600 dark:text-gray-300">
								説明(任意)
							</span>
							<input
								type="text"
								value={editForm.description}
								onChange={(e) =>
									setEditForm({ ...editForm, description: e.target.value })
								}
								className="rounded border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800"
							/>
						</label>
						<div className="flex gap-2">
							<button
								type="submit"
								disabled={pendingId === editingId}
								className="self-start rounded bg-indigo-600 px-4 py-2 text-white disabled:opacity-50"
							>
								更新
							</button>
							<button
								type="button"
								onClick={cancelEdit}
								className="self-start rounded border border-gray-300 px-4 py-2 dark:border-gray-600"
							>
								キャンセル
							</button>
						</div>
					</form>
				)}

				<div className="mb-3 flex items-center justify-between">
					<h2 className="text-lg font-medium">短縮URL一覧</h2>
					{showScopeToggle && (
						<label className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300">
							<input
								type="checkbox"
								checked={scopeMine}
								onChange={(e) => setScopeMine(e.target.checked)}
							/>
							自分のURLのみ表示
						</label>
					)}
				</div>

				{rowError && <p className="mb-4 text-sm text-red-600">{rowError}</p>}
				{listQuery.isLoading && <p>読み込み中…</p>}
				{listQuery.isError && (
					<p className="text-sm text-red-600">一覧の取得に失敗しました</p>
				)}
				{listQuery.data && listQuery.data.length === 0 && (
					<p className="text-gray-500">短縮URLはまだありません。</p>
				)}

				<ul className="flex flex-col gap-3">
					{listQuery.data?.map((su) => {
						const busy = pendingId === su.id;
						return (
							<li
								key={su.id}
								className="rounded border border-gray-200 p-4 dark:border-gray-700"
							>
								<div className="flex items-start justify-between gap-4">
									<div className="min-w-0">
										<a
											href={`${REDIRECT_BASE_URL}/${su.short_code}`}
											target="_blank"
											rel="noreferrer"
											className="font-mono text-indigo-600 underline"
										>
											{REDIRECT_BASE_URL}/{su.short_code}
										</a>
										<p className="truncate text-sm text-gray-500">
											→ {su.long_url}
										</p>
										<p className="mt-1 text-xs text-gray-500">
											{su.status === "disabled" ? "無効化済み" : "有効"}
											{su.your_role
												? ` ・ ${ROLE_LABELS[su.your_role] ?? su.your_role}`
												: " ・ 閲覧のみ(管理者権限)"}
										</p>
									</div>
									<div className="flex shrink-0 gap-2">
										{su.can_edit && (
											<button
												type="button"
												disabled={busy}
												onClick={() => startEdit(su)}
												className="rounded border border-gray-300 px-2 py-1 text-xs disabled:opacity-50 dark:border-gray-600"
											>
												編集
											</button>
										)}
										{su.can_manage_permissions && (
											<Link
												to={`/short-urls/${su.id}/permissions`}
												className="rounded border border-gray-300 px-2 py-1 text-xs dark:border-gray-600"
											>
												権限管理
											</Link>
										)}
										{su.can_delete && (
											<button
												type="button"
												disabled={busy}
												onClick={() => handleDelete(su)}
												className="rounded border border-gray-300 px-2 py-1 text-xs disabled:opacity-50 dark:border-gray-600"
											>
												削除
											</button>
										)}
									</div>
								</div>
							</li>
						);
					})}
				</ul>
			</div>
		</div>
	);
}
