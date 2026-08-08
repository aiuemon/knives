import { type FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError, api } from "../api/client";
import { useAuth } from "../auth/AuthContext";

export function LoginPage() {
	const [email, setEmail] = useState("");
	const [password, setPassword] = useState("");
	const [error, setError] = useState<string | null>(null);
	const [submitting, setSubmitting] = useState(false);
	const navigate = useNavigate();
	const { refetch } = useAuth();

	async function handleSubmit(e: FormEvent) {
		e.preventDefault();
		setError(null);
		setSubmitting(true);
		try {
			await api.post("/auth/local/login", { email, password });
			await refetch();
			navigate("/");
		} catch (err) {
			if (err instanceof ApiError) {
				if (err.status === 401) {
					setError("メールアドレスまたはパスワードが違います");
				} else if (err.status === 429) {
					setError(
						"失敗回数が多いため、アカウントが一時的にロックされています",
					);
				} else {
					setError(err.message);
				}
			} else {
				setError("ログインに失敗しました");
			}
		} finally {
			setSubmitting(false);
		}
	}

	return (
		<div className="mx-auto mt-20 max-w-sm px-4">
			<h1 className="mb-6 text-2xl font-semibold">ログイン</h1>
			<form onSubmit={handleSubmit} className="flex flex-col gap-4">
				<label className="flex flex-col gap-1">
					<span className="text-sm text-gray-600 dark:text-gray-300">
						メールアドレス
					</span>
					<input
						type="email"
						name="email"
						autoComplete="email"
						required
						value={email}
						onChange={(e) => setEmail(e.target.value)}
						className="rounded border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800"
					/>
				</label>
				<label className="flex flex-col gap-1">
					<span className="text-sm text-gray-600 dark:text-gray-300">
						パスワード
					</span>
					<input
						type="password"
						name="current-password"
						autoComplete="current-password"
						required
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
					{submitting ? "ログイン中…" : "ログイン"}
				</button>
			</form>
			<p className="mt-4 text-sm text-gray-600 dark:text-gray-300">
				アカウントが無い場合は{" "}
				<Link to="/signup" className="text-indigo-600 underline">
					サインアップ
				</Link>
			</p>
		</div>
	);
}
