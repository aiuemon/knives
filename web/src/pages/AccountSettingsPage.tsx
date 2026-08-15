import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { ApiError, api } from "../api/client";
import type { WebAuthnCredential } from "../api/types";
import { Header } from "../components/Header";
import { PencilIcon, TrashIcon } from "../components/icons";
import { registerPasskey } from "../lib/webauthn";

const TRANSPORT_LABELS: Record<string, string> = {
	internal: "端末内蔵(指紋・顔認証など)",
	hybrid: "別端末(QRコード連携)",
	usb: "USBセキュリティキー",
	nfc: "NFCセキュリティキー",
	ble: "Bluetoothセキュリティキー",
};

function formatDateTime(iso: string) {
	const d = new Date(iso);
	if (Number.isNaN(d.getTime())) {
		return iso;
	}
	return d.toLocaleString("ja-JP");
}

function transportLabel(cred: WebAuthnCredential) {
	if (!cred.transports || cred.transports.length === 0) {
		return "パスキー";
	}
	return cred.transports.map((t) => TRANSPORT_LABELS[t] ?? t).join(" / ");
}

export function AccountSettingsPage() {
	const queryClient = useQueryClient();
	const [error, setError] = useState<string | null>(null);
	const [newName, setNewName] = useState("");
	const [registering, setRegistering] = useState(false);
	const [revokingId, setRevokingId] = useState<string | null>(null);
	const [editingId, setEditingId] = useState<string | null>(null);
	const [editName, setEditName] = useState("");
	const [savingId, setSavingId] = useState<string | null>(null);

	const credentialsQuery = useQuery({
		queryKey: ["auth", "webauthn", "credentials"],
		queryFn: () => api.get<WebAuthnCredential[]>("/auth/webauthn/credentials"),
	});

	async function handleRegister(e: FormEvent) {
		e.preventDefault();
		setError(null);
		setRegistering(true);
		try {
			await registerPasskey(newName);
			await queryClient.invalidateQueries({
				queryKey: ["auth", "webauthn", "credentials"],
			});
			setNewName("");
		} catch (err) {
			setError(
				err instanceof ApiError ? err.message : "パスキーの登録に失敗しました",
			);
		} finally {
			setRegistering(false);
		}
	}

	async function handleRevoke(cred: WebAuthnCredential) {
		if (!window.confirm("このパスキーを削除しますか?")) {
			return;
		}
		setError(null);
		setRevokingId(cred.id);
		try {
			await api.delete(`/auth/webauthn/credentials/${cred.id}`);
			queryClient.setQueryData<WebAuthnCredential[]>(
				["auth", "webauthn", "credentials"],
				(current) => current?.filter((c) => c.id !== cred.id),
			);
		} catch (err) {
			setError(
				err instanceof ApiError ? err.message : "パスキーの削除に失敗しました",
			);
		} finally {
			setRevokingId(null);
		}
	}

	function startEdit(cred: WebAuthnCredential) {
		setError(null);
		setEditingId(cred.id);
		setEditName(cred.name);
	}

	function cancelEdit() {
		setEditingId(null);
		setEditName("");
	}

	async function handleSaveName(cred: WebAuthnCredential) {
		setError(null);
		setSavingId(cred.id);
		try {
			const updated = await api.patch<WebAuthnCredential>(
				`/auth/webauthn/credentials/${cred.id}`,
				{ name: editName },
			);
			queryClient.setQueryData<WebAuthnCredential[]>(
				["auth", "webauthn", "credentials"],
				(current) => current?.map((c) => (c.id === cred.id ? updated : c)),
			);
			setEditingId(null);
		} catch (err) {
			setError(
				err instanceof ApiError
					? err.message
					: "パスキー名の変更に失敗しました",
			);
		} finally {
			setSavingId(null);
		}
	}

	return (
		<div>
			<Header />
			<div className="mx-auto max-w-3xl px-4 py-8">
				<h1 className="mb-6 text-2xl font-semibold">アカウント設定</h1>

				<h2 className="mb-2 text-lg font-medium">パスキー</h2>
				<p className="mb-4 text-sm text-gray-600 dark:text-gray-300">
					パスキーを登録すると、メールアドレス・パスワードの入力なしで端末の生体認証やセキュリティキーでログインできます。
				</p>

				{error && <p className="mb-4 text-sm text-red-600">{error}</p>}

				<form
					onSubmit={handleRegister}
					className="mb-6 flex flex-wrap items-end gap-3"
				>
					<label className="flex flex-col gap-1 text-sm text-gray-600 dark:text-gray-300">
						名称(任意)
						<input
							type="text"
							value={newName}
							onChange={(e) => setNewName(e.target.value)}
							placeholder="例: 会社支給MacBook"
							className="rounded border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800"
						/>
					</label>
					<button
						type="submit"
						disabled={registering}
						className="rounded bg-indigo-600 px-4 py-2 text-white disabled:opacity-50"
					>
						{registering ? "登録中…" : "パスキーを登録"}
					</button>
				</form>

				{credentialsQuery.isLoading && <p>読み込み中…</p>}
				{credentialsQuery.isError && (
					<p className="text-sm text-red-600">
						パスキー一覧の取得に失敗しました
					</p>
				)}
				{credentialsQuery.data && credentialsQuery.data.length === 0 && (
					<p className="text-gray-500">登録済みのパスキーはありません。</p>
				)}

				{credentialsQuery.data && credentialsQuery.data.length > 0 && (
					<div className="overflow-x-auto">
						<table className="w-full text-left text-sm">
							<thead>
								<tr className="border-b border-gray-200 text-gray-500 dark:border-gray-700 dark:text-gray-400">
									<th className="py-2 pr-4 font-medium">名称</th>
									<th className="py-2 pr-4 font-medium">登録日時</th>
									<th className="py-2 pr-4 font-medium">最終利用日時</th>
									<th className="py-2 pr-4 font-medium" />
								</tr>
							</thead>
							<tbody>
								{credentialsQuery.data.map((cred) => {
									const busy = revokingId === cred.id || savingId === cred.id;
									return (
										<tr
											key={cred.id}
											className="border-b border-gray-100 dark:border-gray-800"
										>
											<td className="py-2 pr-4">
												{editingId === cred.id ? (
													<div className="flex items-center gap-2">
														<input
															type="text"
															value={editName}
															onChange={(e) => setEditName(e.target.value)}
															aria-label="名称"
															className="rounded border border-gray-300 px-2 py-1 dark:border-gray-600 dark:bg-gray-800"
														/>
														<button
															type="button"
															disabled={busy}
															onClick={() => handleSaveName(cred)}
															className="rounded border border-gray-300 px-2 py-1 text-xs disabled:opacity-50 dark:border-gray-600"
														>
															保存
														</button>
														<button
															type="button"
															disabled={busy}
															onClick={cancelEdit}
															className="rounded border border-gray-300 px-2 py-1 text-xs disabled:opacity-50 dark:border-gray-600"
														>
															キャンセル
														</button>
													</div>
												) : (
													<div className="flex items-center gap-2">
														<div>
															<p>{cred.name || "(名称未設定)"}</p>
															<p className="text-xs text-gray-500">
																{transportLabel(cred)}
															</p>
														</div>
														<button
															type="button"
															disabled={busy}
															onClick={() => startEdit(cred)}
															aria-label="編集"
															title="編集"
															className="rounded border border-gray-300 p-1.5 disabled:opacity-50 dark:border-gray-600"
														>
															<PencilIcon />
														</button>
													</div>
												)}
											</td>
											<td className="py-2 pr-4 text-gray-500">
												{formatDateTime(cred.created_at)}
											</td>
											<td className="py-2 pr-4 text-gray-500">
												{cred.last_used_at
													? formatDateTime(cred.last_used_at)
													: "未使用"}
											</td>
											<td className="py-2 pr-4">
												<button
													type="button"
													disabled={busy}
													onClick={() => handleRevoke(cred)}
													aria-label="削除"
													title="削除"
													className="rounded border border-gray-300 p-1.5 disabled:opacity-50 dark:border-gray-600"
												>
													<TrashIcon />
												</button>
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
