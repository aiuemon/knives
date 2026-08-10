import { useQuery } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { ApiError, api } from "../api/client";
import type { PublicSAMLIdP } from "../api/types";
import { useAuth } from "../auth/AuthContext";

export function LoginPage() {
	const [email, setEmail] = useState("");
	const [password, setPassword] = useState("");
	const [error, setError] = useState<string | null>(null);
	const [submitting, setSubmitting] = useState(false);
	const navigate = useNavigate();
	const { refetch } = useAuth();
	const [searchParams] = useSearchParams();

	const idpsQuery = useQuery({
		queryKey: ["auth", "saml", "idps"],
		queryFn: () => api.get<PublicSAMLIdP[]>("/auth/saml/idps"),
		retry: false,
	});

	const notice = searchParams.get("notice");
	const ssoError = searchParams.get("error");

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

			{notice === "saml_pending_confirmation" && (
				<p className="mb-4 rounded border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200">
					確認メールを送信しました。既存アカウントの登録メール宛のリンクから統合を承認してください。
				</p>
			)}
			{ssoError === "saml_failed" && (
				<p className="mb-4 rounded border border-red-300 bg-red-50 p-3 text-sm text-red-900 dark:border-red-700 dark:bg-red-950 dark:text-red-200">
					SSOログインに失敗しました。もう一度お試しください。
				</p>
			)}

			{idpsQuery.data && idpsQuery.data.length > 0 && (
				<div className="mb-6 flex flex-col gap-2">
					{idpsQuery.data.map((idp) => (
						<a
							key={idp.id}
							href={`/api/auth/saml/${idp.id}/login`}
							className="rounded border border-gray-300 px-4 py-2 text-center hover:bg-gray-50 dark:border-gray-600 dark:hover:bg-gray-800"
						>
							{idp.name} でログイン
						</a>
					))}
					<div className="my-2 flex items-center gap-3 text-xs text-gray-400">
						<span className="h-px flex-1 bg-gray-200 dark:bg-gray-700" />
						または
						<span className="h-px flex-1 bg-gray-200 dark:bg-gray-700" />
					</div>
				</div>
			)}

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
