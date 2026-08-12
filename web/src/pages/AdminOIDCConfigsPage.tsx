import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, api } from "../api/client";
import type { OIDCConfig } from "../api/types";
import { Header } from "../components/Header";
import { PencilIcon, PowerIcon, TrashIcon } from "../components/icons";
import { ToggleIconButton } from "../components/ToggleIconButton";

type OIDCConfigForm = {
	name: string;
	issuer: string;
	client_id: string;
	// 編集時に空のままなら既存のシークレットを維持する(サーバは
	// 一度保存したclient_secretを返さないため、フォームには常に空で
	// スタートする)。
	client_secret: string;
	scopesText: string;
	require_email_verified_claim: boolean;
	enabled: boolean;
};

const emptyForm: OIDCConfigForm = {
	name: "",
	issuer: "",
	client_id: "",
	client_secret: "",
	scopesText: "openid email profile",
	require_email_verified_claim: true,
	enabled: false,
};

export function AdminOIDCConfigsPage() {
	const queryClient = useQueryClient();
	const [error, setError] = useState<string | null>(null);
	const [submitting, setSubmitting] = useState(false);
	const [pendingId, setPendingId] = useState<string | null>(null);
	const [editingId, setEditingId] = useState<string | null>(null);
	const [form, setForm] = useState<OIDCConfigForm>(emptyForm);

	const query = useQuery({
		queryKey: ["admin", "oidc-configs"],
		queryFn: () => api.get<OIDCConfig[]>("/admin/oidc-configs"),
	});

	function startEdit(cfg: OIDCConfig) {
		setError(null);
		setEditingId(cfg.id);
		setForm({
			name: cfg.name,
			issuer: cfg.issuer,
			client_id: cfg.client_id,
			client_secret: "",
			scopesText: cfg.scopes.join(" "),
			require_email_verified_claim: cfg.require_email_verified_claim,
			enabled: cfg.enabled,
		});
	}

	function cancelEdit() {
		setEditingId(null);
		setForm(emptyForm);
	}

	function buildRequestBody(f: OIDCConfigForm) {
		return {
			name: f.name,
			issuer: f.issuer,
			client_id: f.client_id,
			client_secret: f.client_secret,
			scopes: f.scopesText.split(/\s+/).filter(Boolean),
			require_email_verified_claim: f.require_email_verified_claim,
			enabled: f.enabled,
		};
	}

	async function handleSubmit(e: FormEvent) {
		e.preventDefault();
		setError(null);
		setSubmitting(true);
		try {
			if (editingId) {
				const updated = await api.patch<OIDCConfig>(
					`/admin/oidc-configs/${editingId}`,
					buildRequestBody(form),
				);
				queryClient.setQueryData<OIDCConfig[]>(
					["admin", "oidc-configs"],
					(current) => current?.map((c) => (c.id === editingId ? updated : c)),
				);
			} else {
				const created = await api.post<OIDCConfig>(
					"/admin/oidc-configs",
					buildRequestBody(form),
				);
				queryClient.setQueryData<OIDCConfig[]>(
					["admin", "oidc-configs"],
					(current) => (current ? [...current, created] : [created]),
				);
			}
			cancelEdit();
		} catch (err) {
			setError(err instanceof ApiError ? err.message : "保存に失敗しました");
		} finally {
			setSubmitting(false);
		}
	}

	async function handleToggleEnabled(cfg: OIDCConfig) {
		setError(null);
		setPendingId(cfg.id);
		try {
			const updated = await api.patch<OIDCConfig>(
				`/admin/oidc-configs/${cfg.id}`,
				{
					name: cfg.name,
					issuer: cfg.issuer,
					client_id: cfg.client_id,
					scopes: cfg.scopes,
					require_email_verified_claim: cfg.require_email_verified_claim,
					enabled: !cfg.enabled,
				},
			);
			queryClient.setQueryData<OIDCConfig[]>(
				["admin", "oidc-configs"],
				(current) => current?.map((c) => (c.id === cfg.id ? updated : c)),
			);
		} catch (err) {
			setError(err instanceof ApiError ? err.message : "更新に失敗しました");
		} finally {
			setPendingId(null);
		}
	}

	async function handleDelete(cfg: OIDCConfig) {
		if (!window.confirm(`「${cfg.name}」を削除しますか?`)) {
			return;
		}
		setError(null);
		setPendingId(cfg.id);
		try {
			await api.delete(`/admin/oidc-configs/${cfg.id}`);
			queryClient.setQueryData<OIDCConfig[]>(
				["admin", "oidc-configs"],
				(current) => current?.filter((c) => c.id !== cfg.id),
			);
		} catch (err) {
			setError(err instanceof ApiError ? err.message : "削除に失敗しました");
		} finally {
			setPendingId(null);
		}
	}

	return (
		<div>
			<Header />
			<div className="mx-auto max-w-3xl px-4 py-8">
				<h1 className="mb-2 text-2xl font-semibold">OIDC設定</h1>
				<nav className="mb-6 flex gap-4 text-sm">
					<Link
						to="/admin/settings"
						className="text-gray-600 hover:underline dark:text-gray-300"
					>
						認証設定
					</Link>
					<Link
						to="/admin/users"
						className="text-gray-600 hover:underline dark:text-gray-300"
					>
						ユーザー管理
					</Link>
					<Link
						to="/admin/saml"
						className="text-gray-600 hover:underline dark:text-gray-300"
					>
						SAML設定
					</Link>
					<span className="font-medium text-indigo-600">OIDC設定</span>
				</nav>

				{error && <p className="mb-4 text-sm text-red-600">{error}</p>}

				<form
					onSubmit={handleSubmit}
					className="mb-10 flex flex-col gap-4 rounded border border-gray-200 p-4 dark:border-gray-700"
				>
					<h2 className="text-lg font-medium">
						{editingId ? "IdP設定を編集" : "IdPを追加"}
					</h2>
					<label className="flex flex-col gap-1">
						<span className="text-sm text-gray-600 dark:text-gray-300">
							表示名
						</span>
						<input
							type="text"
							required
							value={form.name}
							onChange={(e) => setForm({ ...form, name: e.target.value })}
							className="rounded border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800"
						/>
					</label>
					<label className="flex flex-col gap-1">
						<span className="text-sm text-gray-600 dark:text-gray-300">
							Issuer URL
						</span>
						<input
							type="url"
							required
							value={form.issuer}
							onChange={(e) => setForm({ ...form, issuer: e.target.value })}
							placeholder="https://login.microsoftonline.com/{tenant}/v2.0"
							className="rounded border border-gray-300 px-3 py-2 font-mono text-sm dark:border-gray-600 dark:bg-gray-800"
						/>
					</label>
					<label className="flex flex-col gap-1">
						<span className="text-sm text-gray-600 dark:text-gray-300">
							Client ID
						</span>
						<input
							type="text"
							required
							value={form.client_id}
							onChange={(e) => setForm({ ...form, client_id: e.target.value })}
							className="rounded border border-gray-300 px-3 py-2 font-mono text-sm dark:border-gray-600 dark:bg-gray-800"
						/>
					</label>
					<label className="flex flex-col gap-1">
						<span className="text-sm text-gray-600 dark:text-gray-300">
							Client Secret
							{editingId && "(変更する場合のみ入力)"}
						</span>
						<input
							type="password"
							required={!editingId}
							autoComplete="new-password"
							value={form.client_secret}
							onChange={(e) =>
								setForm({ ...form, client_secret: e.target.value })
							}
							placeholder={editingId ? "(既存のシークレットを維持)" : undefined}
							className="rounded border border-gray-300 px-3 py-2 font-mono text-sm dark:border-gray-600 dark:bg-gray-800"
						/>
					</label>
					<label className="flex flex-col gap-1">
						<span className="text-sm text-gray-600 dark:text-gray-300">
							スコープ(空白区切り、openid必須)
						</span>
						<input
							type="text"
							required
							value={form.scopesText}
							onChange={(e) => setForm({ ...form, scopesText: e.target.value })}
							className="rounded border border-gray-300 px-3 py-2 font-mono text-sm dark:border-gray-600 dark:bg-gray-800"
						/>
					</label>
					<label className="flex items-start gap-3">
						<input
							type="checkbox"
							checked={form.require_email_verified_claim}
							onChange={(e) =>
								setForm({
									...form,
									require_email_verified_claim: e.target.checked,
								})
							}
							className="mt-1"
						/>
						<span className="text-sm">
							email_verifiedクレームがtrueの場合のみ既存アカウントへ自動統合する(OFFの場合、このIdPからのログインは常に確認メールフローに回る)
						</span>
					</label>
					<label className="flex items-start gap-3">
						<input
							type="checkbox"
							checked={form.enabled}
							onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
							className="mt-1"
						/>
						<span className="text-sm">有効にする</span>
					</label>
					<div className="flex gap-2">
						<button
							type="submit"
							disabled={submitting}
							className="self-start rounded bg-indigo-600 px-4 py-2 text-white disabled:opacity-50"
						>
							{submitting ? "保存中…" : editingId ? "更新" : "追加"}
						</button>
						{editingId && (
							<button
								type="button"
								onClick={cancelEdit}
								className="self-start rounded border border-gray-300 px-4 py-2 dark:border-gray-600"
							>
								キャンセル
							</button>
						)}
					</div>
				</form>

				<h2 className="mb-3 text-lg font-medium">登録済みのIdP</h2>
				{query.isLoading && <p>読み込み中…</p>}
				{query.isError && (
					<p className="text-sm text-red-600">一覧の取得に失敗しました</p>
				)}
				{query.data && query.data.length === 0 && (
					<p className="text-gray-500">登録されているIdPはありません。</p>
				)}
				<ul className="flex flex-col gap-3">
					{query.data?.map((cfg) => {
						const busy = pendingId === cfg.id;
						return (
							<li
								key={cfg.id}
								className="rounded border border-gray-200 p-4 dark:border-gray-700"
							>
								<div className="flex items-start justify-between gap-4">
									<div>
										<p className="font-medium">{cfg.name}</p>
										<p className="text-xs text-gray-500">{cfg.issuer}</p>
										<p className="mt-1 text-xs text-gray-500">
											{cfg.enabled ? "有効" : "無効"} ・{" "}
											{cfg.require_email_verified_claim
												? "email_verified必須(自動統合あり)"
												: "常に確認メール"}
										</p>
									</div>
									<div className="flex shrink-0 gap-1">
										<ToggleIconButton
											active={cfg.enabled}
											color="green"
											icon={<PowerIcon />}
											disabled={busy}
											ariaLabel={cfg.enabled ? "無効化" : "有効化"}
											onClick={() => handleToggleEnabled(cfg)}
										/>
										<button
											type="button"
											disabled={busy}
											onClick={() => startEdit(cfg)}
											aria-label="編集"
											title="編集"
											className="rounded border border-gray-300 p-1.5 disabled:opacity-50 dark:border-gray-600"
										>
											<PencilIcon />
										</button>
										<button
											type="button"
											disabled={busy}
											onClick={() => handleDelete(cfg)}
											aria-label="削除"
											title="削除"
											className="rounded border border-gray-300 p-1.5 disabled:opacity-50 dark:border-gray-600"
										>
											<TrashIcon />
										</button>
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
