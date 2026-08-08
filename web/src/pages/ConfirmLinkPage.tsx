import { useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { ApiError, api } from "../api/client";
import { useAuth } from "../auth/AuthContext";

type Status = "loading" | "success" | "error";

// レガシーモード(auth_settings.require_reauth_for_account_link = false)専用:
// リンクを開いた時点で即座に承認が完了する。既定(true)の環境では
// このページではなく PendingLinksPage 経由で承認する。
export function ConfirmLinkPage() {
	const [params] = useSearchParams();
	const token = params.get("token");
	const [status, setStatus] = useState<Status>("loading");
	const [message, setMessage] = useState<string | null>(null);
	const { refetch } = useAuth();
	const navigate = useNavigate();
	const started = useRef(false);

	useEffect(() => {
		if (started.current) return;
		started.current = true;

		if (!token) {
			setStatus("error");
			setMessage("トークンがありません");
			return;
		}

		api
			.get<{ status: string }>(
				`/auth/confirm-link?token=${encodeURIComponent(token)}`,
			)
			.then(async () => {
				await refetch();
				setStatus("success");
			})
			.catch((err: unknown) => {
				setStatus("error");
				if (err instanceof ApiError) {
					if (err.status === 410) setMessage("リンクの有効期限が切れています");
					else if (err.status === 409)
						setMessage("このリンクは既に使用されています");
					else setMessage(err.message);
				} else {
					setMessage("確認に失敗しました");
				}
			});
	}, [token, refetch]);

	return (
		<div className="mx-auto mt-20 max-w-sm px-4 text-center">
			<h1 className="mb-6 text-2xl font-semibold">ログイン方法の追加を承認</h1>
			{status === "loading" && <p>確認中…</p>}
			{status === "success" && (
				<div>
					<p className="mb-4 text-green-700 dark:text-green-400">
						承認しました。ログインしました。
					</p>
					<button
						type="button"
						onClick={() => navigate("/")}
						className="rounded bg-indigo-600 px-4 py-2 text-white"
					>
						ダッシュボードへ
					</button>
				</div>
			)}
			{status === "error" && <p className="text-red-600">{message}</p>}
		</div>
	);
}
