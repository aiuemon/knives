import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, api } from "../api/client";
import type {
	ShortURL,
	ShortURLListItem,
	ShortURLListResponse,
	ShortURLSortField,
	SortDirection,
} from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { Header } from "../components/Header";
import { ChartIcon, KeyIcon, PencilIcon, TrashIcon } from "../components/icons";

const REDIRECT_BASE_URL =
	import.meta.env.VITE_REDIRECT_BASE_URL ?? "http://localhost:8081";

const ROLE_LABELS: Record<string, string> = {
	owner: "オーナー",
	editor: "編集者",
	viewer: "閲覧者",
};

const PAGE_SIZE_OPTIONS = [15, 50, 100] as const;
const DEFAULT_PAGE_SIZE = 15;

const SORT_COLUMNS: { field: ShortURLSortField; label: string }[] = [
	{ field: "short_code", label: "短縮URL" },
	{ field: "long_url", label: "リダイレクト先URL" },
	{ field: "title", label: "タイトル" },
	{ field: "created_at", label: "登録日時" },
	{ field: "click_count", label: "クリック数" },
	{ field: "creator_email", label: "登録者" },
];

type EditForm = {
	long_url: string;
	title: string;
	description: string;
};

const emptyEditForm: EditForm = { long_url: "", title: "", description: "" };

function formatDateTime(iso: string) {
	const d = new Date(iso);
	if (Number.isNaN(d.getTime())) {
		return iso;
	}
	return d.toLocaleString("ja-JP");
}

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

	const [filterInput, setFilterInput] = useState("");
	const [filter, setFilter] = useState("");
	const [pageSize, setPageSize] = useState<number>(DEFAULT_PAGE_SIZE);
	const [offset, setOffset] = useState(0);
	const [sortBy, setSortBy] = useState<ShortURLSortField>("created_at");
	const [sortDir, setSortDir] = useState<SortDirection>("desc");

	// フィルタ入力は300msデバウンスしてから実際のクエリに反映する
	// (キー入力のたびにAPIを叩かないようにするため)。
	useEffect(() => {
		const t = setTimeout(() => {
			setFilter(filterInput);
			setOffset(0);
		}, 300);
		return () => clearTimeout(t);
	}, [filterInput]);

	const showScopeToggle = user?.is_system_admin ?? false;
	// scope=mine only affects an admin's view server-side (非adminは常に自分の
	// URLのみ、4.1節) — deriving this from scopeMine alone (rather than
	// gating on showScopeToggle, which flips once /auth/me resolves) keeps
	// the query key stable across that async user-load, avoiding a
	// spurious loading-state flicker on every page load.
	const effectiveScopeMine = scopeMine;
	const showCreatorEmail = user?.is_system_admin ?? false;

	const queryKey = [
		"short-urls",
		{
			mine: effectiveScopeMine,
			limit: pageSize,
			offset,
			filter,
			sortBy,
			sortDir,
		},
	] as const;

	const listQuery = useQuery({
		queryKey,
		queryFn: () => {
			const params = new URLSearchParams({
				limit: String(pageSize),
				offset: String(offset),
				sort_by: sortBy,
				sort_dir: sortDir,
			});
			if (filter) {
				params.set("filter", filter);
			}
			if (effectiveScopeMine) {
				params.set("scope", "mine");
			}
			return api.get<ShortURLListResponse>(`/short-urls?${params}`);
		},
	});

	const total = listQuery.data?.total ?? 0;
	const items = listQuery.data?.items ?? [];
	const pageStart = total === 0 ? 0 : offset + 1;
	const pageEnd = Math.min(offset + pageSize, total);

	function toggleSort(field: ShortURLSortField) {
		if (field === sortBy) {
			setSortDir(sortDir === "asc" ? "desc" : "asc");
		} else {
			setSortBy(field);
			setSortDir("asc");
		}
		setOffset(0);
	}

	function changePageSize(size: number) {
		setPageSize(size);
		setOffset(0);
	}

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
			const newItem: ShortURLListItem = { ...su, click_count: 0 };
			queryClient.setQueryData<ShortURLListResponse>(queryKey, (current) =>
				current
					? { items: [newItem, ...current.items], total: current.total + 1 }
					: { items: [newItem], total: 1 },
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

	function startEdit(su: ShortURLListItem) {
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
			queryClient.setQueryData<ShortURLListResponse>(queryKey, (current) =>
				current
					? {
							...current,
							items: current.items.map((su) =>
								su.id === editingId ? { ...su, ...updated } : su,
							),
						}
					: current,
			);
			cancelEdit();
		} catch (err) {
			setRowError(err instanceof ApiError ? err.message : "更新に失敗しました");
		} finally {
			setPendingId(null);
		}
	}

	async function handleDelete(su: ShortURLListItem) {
		if (!window.confirm(`「${su.short_code}」を削除しますか?`)) {
			return;
		}
		setRowError(null);
		setPendingId(su.id);
		try {
			await api.delete(`/short-urls/${su.id}`);
			queryClient.setQueryData<ShortURLListResponse>(queryKey, (current) =>
				current
					? {
							items: current.items.filter((item) => item.id !== su.id),
							total: current.total - 1,
						}
					: current,
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
			<div className="mx-auto max-w-5xl px-4 py-8">
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

				<div className="mb-3 flex flex-wrap items-center justify-between gap-3">
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

				<div className="mb-4 flex flex-wrap items-center gap-4">
					<label className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300">
						フィルタ
						<input
							type="text"
							value={filterInput}
							onChange={(e) => setFilterInput(e.target.value)}
							placeholder="短縮URL・URL・タイトル・登録者で検索"
							className="rounded border border-gray-300 px-3 py-1.5 dark:border-gray-600 dark:bg-gray-800"
						/>
					</label>
					<label className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300">
						表示件数
						<select
							value={pageSize}
							onChange={(e) => changePageSize(Number(e.target.value))}
							className="rounded border border-gray-300 px-2 py-1.5 dark:border-gray-600 dark:bg-gray-800"
						>
							{PAGE_SIZE_OPTIONS.map((size) => (
								<option key={size} value={size}>
									{size}件
								</option>
							))}
						</select>
					</label>
				</div>

				{rowError && <p className="mb-4 text-sm text-red-600">{rowError}</p>}
				{listQuery.isLoading && <p>読み込み中…</p>}
				{listQuery.isError && (
					<p className="text-sm text-red-600">一覧の取得に失敗しました</p>
				)}
				{listQuery.data && items.length === 0 && (
					<p className="text-gray-500">短縮URLはまだありません。</p>
				)}

				{items.length > 0 && (
					<div className="overflow-x-auto">
						<table className="w-full min-w-[720px] border-collapse text-sm">
							<thead>
								<tr className="border-b border-gray-200 text-left dark:border-gray-700">
									{SORT_COLUMNS.filter(
										(col) => col.field !== "creator_email" || showCreatorEmail,
									).map((col) => (
										<th key={col.field} className="px-2 py-2 font-medium">
											<button
												type="button"
												onClick={() => toggleSort(col.field)}
												className="flex items-center gap-1"
											>
												{col.label}
												{sortBy === col.field && (
													<span aria-hidden="true">
														{sortDir === "asc" ? "▲" : "▼"}
													</span>
												)}
											</button>
										</th>
									))}
									<th className="px-2 py-2 font-medium">操作</th>
								</tr>
							</thead>
							<tbody>
								{items.map((su) => {
									const busy = pendingId === su.id;
									return (
										<tr
											key={su.id}
											className="border-b border-gray-100 align-top dark:border-gray-800"
										>
											<td className="px-2 py-3">
												<a
													href={`${REDIRECT_BASE_URL}/${su.short_code}`}
													target="_blank"
													rel="noreferrer"
													className="font-mono text-indigo-600 underline"
												>
													{su.short_code}
												</a>
												<p className="mt-1 text-xs text-gray-500">
													{su.status === "disabled" ? "無効化済み" : "有効"}
													{su.your_role
														? ` ・ ${ROLE_LABELS[su.your_role] ?? su.your_role}`
														: " ・ 閲覧のみ(管理者権限)"}
												</p>
											</td>
											<td className="max-w-xs truncate px-2 py-3">
												{su.long_url}
											</td>
											<td className="px-2 py-3">{su.title || "-"}</td>
											<td className="whitespace-nowrap px-2 py-3">
												{formatDateTime(su.created_at)}
											</td>
											<td className="px-2 py-3">{su.click_count}</td>
											{showCreatorEmail && (
												<td className="px-2 py-3">{su.creator_email ?? "-"}</td>
											)}
											<td className="px-2 py-3">
												<div className="flex gap-1">
													<Link
														to={`/short-urls/${su.id}/stats`}
														aria-label="統計"
														title="統計"
														className="rounded border border-gray-300 p-1.5 dark:border-gray-600"
													>
														<ChartIcon />
													</Link>
													{su.can_edit && (
														<button
															type="button"
															disabled={busy}
															onClick={() => startEdit(su)}
															aria-label="編集"
															title="編集"
															className="rounded border border-gray-300 p-1.5 disabled:opacity-50 dark:border-gray-600"
														>
															<PencilIcon />
														</button>
													)}
													{su.can_manage_permissions && (
														<Link
															to={`/short-urls/${su.id}/permissions`}
															aria-label="権限管理"
															title="権限管理"
															className="rounded border border-gray-300 p-1.5 dark:border-gray-600"
														>
															<KeyIcon />
														</Link>
													)}
													{su.can_delete && (
														<button
															type="button"
															disabled={busy}
															onClick={() => handleDelete(su)}
															aria-label="削除"
															title="削除"
															className="rounded border border-gray-300 p-1.5 disabled:opacity-50 dark:border-gray-600"
														>
															<TrashIcon />
														</button>
													)}
												</div>
											</td>
										</tr>
									);
								})}
							</tbody>
						</table>
					</div>
				)}

				{total > 0 && (
					<div className="mt-4 flex items-center justify-between text-sm text-gray-600 dark:text-gray-300">
						<span>
							{pageStart}–{pageEnd} / {total}件
						</span>
						<div className="flex gap-2">
							<button
								type="button"
								disabled={offset === 0}
								onClick={() => setOffset(Math.max(0, offset - pageSize))}
								className="rounded border border-gray-300 px-3 py-1 disabled:opacity-50 dark:border-gray-600"
							>
								前へ
							</button>
							<button
								type="button"
								disabled={offset + pageSize >= total}
								onClick={() => setOffset(offset + pageSize)}
								className="rounded border border-gray-300 px-3 py-1 disabled:opacity-50 dark:border-gray-600"
							>
								次へ
							</button>
						</div>
					</div>
				)}
			</div>
		</div>
	);
}
