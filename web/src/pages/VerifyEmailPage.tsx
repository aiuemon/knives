import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { ApiError, api } from "../api/client";
import { useAuth } from "../auth/AuthContext";

type Status = "loading" | "success" | "pending" | "error";

export function VerifyEmailPage() {
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
				`/auth/local/verify-email?token=${encodeURIComponent(token)}`,
			)
			.then(async (res) => {
				if (res.status === "verification_pending") {
					setStatus("pending");
					setMessage(
						"メール到達確認は完了しましたが、このメールは既に別アカウントにクレーム済みのため、そちらの確認メールをお待ちください。",
					);
					return;
				}
				await refetch();
				setStatus("success");
			})
			.catch((err: unknown) => {
				setStatus("error");
				if (err instanceof ApiError) {
					if (err.status === 410) setMessage("リンクの有効期限が切れています");
					else if (err.status === 404) setMessage("無効なリンクです");
					else setMessage(err.message);
				} else {
					setMessage("確認に失敗しました");
				}
			});
	}, [token, refetch]);

	return (
		<div className="mx-auto mt-20 max-w-sm px-4 text-center">
			<h1 className="mb-6 text-2xl font-semibold">メールアドレスの確認</h1>
			{status === "loading" && <p>確認中…</p>}
			{status === "success" && (
				<div>
					<p className="mb-4 text-green-700 dark:text-green-400">
						登録が完了しました。
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
			{status === "pending" && (
				<p className="text-amber-700 dark:text-amber-400">{message}</p>
			)}
			{status === "error" && (
				<div>
					<p className="mb-4 text-red-600">{message}</p>
					<Link to="/signup" className="text-indigo-600 underline">
						サインアップをやり直す
					</Link>
				</div>
			)}
		</div>
	);
}
