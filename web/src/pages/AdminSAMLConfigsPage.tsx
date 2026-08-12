import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, api } from "../api/client";
import type { SAMLConfig } from "../api/types";
import { Header } from "../components/Header";
import { PencilIcon, PowerIcon, TrashIcon } from "../components/icons";
import { ToggleIconButton } from "../components/ToggleIconButton";

type SAMLConfigForm = {
	name: string;
	idp_entity_id: string;
	idp_sso_url: string;
	idp_certificate: string;
	email_attribute: string;
	trusted: boolean;
	enabled: boolean;
};

const emptyForm: SAMLConfigForm = {
	name: "",
	idp_entity_id: "",
	idp_sso_url: "",
	idp_certificate: "",
	email_attribute: "",
	trusted: false,
	enabled: false,
};

export function AdminSAMLConfigsPage() {
	const queryClient = useQueryClient();
	const [error, setError] = useState<string | null>(null);
	const [submitting, setSubmitting] = useState(false);
	const [pendingId, setPendingId] = useState<string | null>(null);
	const [editingId, setEditingId] = useState<string | null>(null);
	const [form, setForm] = useState<SAMLConfigForm>(emptyForm);

	const query = useQuery({
		queryKey: ["admin", "saml-configs"],
		queryFn: () => api.get<SAMLConfig[]>("/admin/saml-configs"),
	});

	function startEdit(cfg: SAMLConfig) {
		setError(null);
		setEditingId(cfg.id);
		setForm({
			name: cfg.name,
			idp_entity_id: cfg.idp_entity_id,
			idp_sso_url: cfg.idp_sso_url,
			idp_certificate: cfg.idp_certificate,
			email_attribute: cfg.email_attribute,
			trusted: cfg.trusted,
			enabled: cfg.enabled,
		});
	}

	function cancelEdit() {
		setEditingId(null);
		setForm(emptyForm);
	}

	async function handleSubmit(e: FormEvent) {
		e.preventDefault();
		setError(null);
		setSubmitting(true);
		try {
			if (editingId) {
				const updated = await api.patch<SAMLConfig>(
					`/admin/saml-configs/${editingId}`,
					form,
				);
				queryClient.setQueryData<SAMLConfig[]>(
					["admin", "saml-configs"],
					(current) => current?.map((c) => (c.id === editingId ? updated : c)),
				);
			} else {
				const created = await api.post<SAMLConfig>("/admin/saml-configs", form);
				queryClient.setQueryData<SAMLConfig[]>(
					["admin", "saml-configs"],
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

	async function handleToggleEnabled(cfg: SAMLConfig) {
		setError(null);
		setPendingId(cfg.id);
		try {
			const updated = await api.patch<SAMLConfig>(
				`/admin/saml-configs/${cfg.id}`,
				{ ...cfg, enabled: !cfg.enabled },
			);
			queryClient.setQueryData<SAMLConfig[]>(
				["admin", "saml-configs"],
				(current) => current?.map((c) => (c.id === cfg.id ? updated : c)),
			);
		} catch (err) {
			setError(err instanceof ApiError ? err.message : "更新に失敗しました");
		} finally {
			setPendingId(null);
		}
	}

	async function handleDelete(cfg: SAMLConfig) {
		if (!window.confirm(`「${cfg.name}」を削除しますか?`)) {
			return;
		}
		setError(null);
		setPendingId(cfg.id);
		try {
			await api.delete(`/admin/saml-configs/${cfg.id}`);
			queryClient.setQueryData<SAMLConfig[]>(
				["admin", "saml-configs"],
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
				<h1 className="mb-2 text-2xl font-semibold">SAML設定</h1>
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
					<span className="font-medium text-indigo-600">SAML設定</span>
					<Link
						to="/admin/oidc"
						className="text-gray-600 hover:underline dark:text-gray-300"
					>
						OIDC設定
					</Link>
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
							IdP Entity ID
						</span>
						<input
							type="text"
							required
							value={form.idp_entity_id}
							onChange={(e) =>
								setForm({ ...form, idp_entity_id: e.target.value })
							}
							className="rounded border border-gray-300 px-3 py-2 font-mono text-sm dark:border-gray-600 dark:bg-gray-800"
						/>
					</label>
					<label className="flex flex-col gap-1">
						<span className="text-sm text-gray-600 dark:text-gray-300">
							IdP SSO URL
						</span>
						<input
							type="url"
							required
							value={form.idp_sso_url}
							onChange={(e) =>
								setForm({ ...form, idp_sso_url: e.target.value })
							}
							className="rounded border border-gray-300 px-3 py-2 font-mono text-sm dark:border-gray-600 dark:bg-gray-800"
						/>
					</label>
					<label className="flex flex-col gap-1">
						<span className="text-sm text-gray-600 dark:text-gray-300">
							IdP証明書(PEM形式)
						</span>
						<textarea
							required
							rows={6}
							value={form.idp_certificate}
							onChange={(e) =>
								setForm({ ...form, idp_certificate: e.target.value })
							}
							placeholder="-----BEGIN CERTIFICATE-----"
							className="rounded border border-gray-300 px-3 py-2 font-mono text-xs dark:border-gray-600 dark:bg-gray-800"
						/>
					</label>
					<label className="flex flex-col gap-1">
						<span className="text-sm text-gray-600 dark:text-gray-300">
							メールアドレスの属性名
						</span>
						<input
							type="text"
							required
							value={form.email_attribute}
							onChange={(e) =>
								setForm({ ...form, email_attribute: e.target.value })
							}
							placeholder="email"
							className="rounded border border-gray-300 px-3 py-2 font-mono text-sm dark:border-gray-600 dark:bg-gray-800"
						/>
					</label>
					<label className="flex items-start gap-3">
						<input
							type="checkbox"
							checked={form.trusted}
							onChange={(e) => setForm({ ...form, trusted: e.target.checked })}
							className="mt-1"
						/>
						<span className="text-sm">
							信頼済みIdPとして扱う(組織が完全管理するIdP向け。ONの場合、既存アカウントへの統合を確認メールなしで自動的に行う)
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
										<p className="text-xs text-gray-500">{cfg.idp_entity_id}</p>
										<p className="mt-1 text-xs text-gray-500">
											{cfg.enabled ? "有効" : "無効"} ・{" "}
											{cfg.trusted ? "信頼済み" : "未信頼(確認メール必須)"}
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
