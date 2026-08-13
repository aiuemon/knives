import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError, api } from "../api/client";
import type { WebAuthnCredential } from "../api/types";
import { Header } from "../components/Header";
import { TrashIcon } from "../components/icons";
import { registerPasskey } from "../lib/webauthn";

const TRANSPORT_LABELS: Record<string, string> = {
	internal: "端末内蔵(指紋・顔認証など)",
	hybrid: "別端末(QRコード連携)",
	usb: "USBセキュリティキー",
	nfc: "NFCセキュリティキー",
	ble: "Bluetoothセキュリティキー",
};

export function AccountSettingsPage() {
	const queryClient = useQueryClient();
	const [error, setError] = useState<string | null>(null);
	const [registering, setRegistering] = useState(false);
	const [revokingId, setRevokingId] = useState<string | null>(null);

	const credentialsQuery = useQuery({
		queryKey: ["auth", "webauthn", "credentials"],
		queryFn: () => api.get<WebAuthnCredential[]>("/auth/webauthn/credentials"),
	});

	async function handleRegister() {
		setError(null);
		setRegistering(true);
		try {
			await registerPasskey();
			await queryClient.invalidateQueries({
				queryKey: ["auth", "webauthn", "credentials"],
			});
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

	return (
		<div>
			<Header />
			<div className="mx-auto max-w-2xl px-4 py-8">
				<h1 className="mb-6 text-2xl font-semibold">アカウント設定</h1>

				<h2 className="mb-2 text-lg font-medium">パスキー</h2>
				<p className="mb-4 text-sm text-gray-600 dark:text-gray-300">
					パスキーを登録すると、メールアドレス・パスワードの入力なしで端末の生体認証やセキュリティキーでログインできます。
				</p>

				{error && <p className="mb-4 text-sm text-red-600">{error}</p>}

				<button
					type="button"
					disabled={registering}
					onClick={handleRegister}
					className="mb-6 rounded bg-indigo-600 px-4 py-2 text-white disabled:opacity-50"
				>
					{registering ? "登録中…" : "パスキーを登録"}
				</button>

				{credentialsQuery.isLoading && <p>読み込み中…</p>}
				{credentialsQuery.isError && (
					<p className="text-sm text-red-600">
						パスキー一覧の取得に失敗しました
					</p>
				)}
				{credentialsQuery.data && credentialsQuery.data.length === 0 && (
					<p className="text-gray-500">登録済みのパスキーはありません。</p>
				)}

				<ul className="flex flex-col gap-2">
					{credentialsQuery.data?.map((cred) => (
						<li
							key={cred.id}
							className="flex items-center justify-between rounded border border-gray-200 p-3 text-sm dark:border-gray-700"
						>
							<span>
								{cred.transports && cred.transports.length > 0
									? cred.transports
											.map((t) => TRANSPORT_LABELS[t] ?? t)
											.join(" / ")
									: "パスキー"}
							</span>
							<button
								type="button"
								disabled={revokingId === cred.id}
								onClick={() => handleRevoke(cred)}
								aria-label="削除"
								title="削除"
								className="rounded border border-gray-300 p-1.5 disabled:opacity-50 dark:border-gray-600"
							>
								<TrashIcon />
							</button>
						</li>
					))}
				</ul>
			</div>
		</div>
	);
}
