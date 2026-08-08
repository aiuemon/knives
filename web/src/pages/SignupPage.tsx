import { type FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError, api } from "../api/client";
import type { SignupResponse } from "../api/types";
import { useAuth } from "../auth/AuthContext";

export function SignupPage() {
	const [email, setEmail] = useState("");
	const [password, setPassword] = useState("");
	const [error, setError] = useState<string | null>(null);
	const [pendingMessage, setPendingMessage] = useState<string | null>(null);
	const [submitting, setSubmitting] = useState(false);
	const navigate = useNavigate();
	const { refetch } = useAuth();

	async function handleSubmit(e: FormEvent) {
		e.preventDefault();
		setError(null);
		setPendingMessage(null);
		setSubmitting(true);
		try {
			const res = await api.post<SignupResponse>("/auth/local/signup", {
				email,
				password,
			});
			if (res.status === "verification_pending") {
				setPendingMessage(
					"確認メールを送信しました(このローカル環境ではSMTP未設定のため、api serverのログに verify_url が出力されます)。リンクを開くと登録が完了します。",
				);
				return;
			}
			await refetch();
			navigate("/");
		} catch (err) {
			if (err instanceof ApiError) {
				if (err.status === 403) {
					setError("セルフサインアップは現在無効になっています");
				} else if (err.status === 400) {
					setError(err.message || "入力内容を確認してください");
				} else {
					setError(err.message);
				}
			} else {
				setError("サインアップに失敗しました");
			}
		} finally {
			setSubmitting(false);
		}
	}

	return (
		<div className="mx-auto mt-20 max-w-sm px-4">
			<h1 className="mb-6 text-2xl font-semibold">サインアップ</h1>
			{pendingMessage ? (
				<p className="rounded border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200">
					{pendingMessage}
				</p>
			) : (
				<form onSubmit={handleSubmit} className="flex flex-col gap-4">
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
							パスワード(8文字以上)
						</span>
						<input
							type="password"
							required
							minLength={8}
							value={password}
							onChange={(e) => setPassword(e.target.value)}
							className="rounded border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800"
						/>
					</label>
					{error && <p className="text-sm text-red-600">{error}</p>}
					<button
						type="submit"
						disabled={submitting}
						className="rounded bg-indigo-600 px-4 py-2 text-white disabled:opacity-50"
					>
						{submitting ? "送信中…" : "サインアップ"}
					</button>
				</form>
			)}
			<p className="mt-4 text-sm text-gray-600 dark:text-gray-300">
				アカウントをお持ちの場合は{" "}
				<Link to="/login" className="text-indigo-600 underline">
					ログイン
				</Link>
			</p>
		</div>
	);
}
