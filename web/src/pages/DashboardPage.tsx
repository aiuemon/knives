import { type FormEvent, useState } from "react";
import { ApiError, api } from "../api/client";
import type { ShortURL } from "../api/types";
import { Header } from "../components/Header";

const REDIRECT_BASE_URL =
	import.meta.env.VITE_REDIRECT_BASE_URL ?? "http://localhost:8081";

export function DashboardPage() {
	const [longUrl, setLongUrl] = useState("");
	const [customAlias, setCustomAlias] = useState("");
	const [title, setTitle] = useState("");
	const [error, setError] = useState<string | null>(null);
	const [submitting, setSubmitting] = useState(false);
	const [created, setCreated] = useState<ShortURL[]>([]);

	const [lookupId, setLookupId] = useState("");
	const [lookupResult, setLookupResult] = useState<ShortURL | null>(null);
	const [lookupError, setLookupError] = useState<string | null>(null);

	async function handleCreate(e: FormEvent) {
		e.preventDefault();
		setError(null);
		setSubmitting(true);
		try {
			const su = await api.post<ShortURL>("/short-urls", {
				long_url: longUrl,
				custom_alias: customAlias || undefined,
				title: title || undefined,
			});
			setCreated((prev) => [su, ...prev]);
			setLongUrl("");
			setCustomAlias("");
			setTitle("");
		} catch (err) {
			setError(err instanceof ApiError ? err.message : "作成に失敗しました");
		} finally {
			setSubmitting(false);
		}
	}

	async function handleLookup(e: FormEvent) {
		e.preventDefault();
		setLookupError(null);
		setLookupResult(null);
		try {
			const su = await api.get<ShortURL>(`/short-urls/${lookupId}`);
			setLookupResult(su);
		} catch (err) {
			setLookupError(
				err instanceof ApiError && err.status === 404
					? "見つかりませんでした"
					: "検索に失敗しました",
			);
		}
	}

	return (
		<div>
			<Header />
			<div className="mx-auto max-w-2xl px-4 py-8">
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
					{error && <p className="text-sm text-red-600">{error}</p>}
					<button
						type="submit"
						disabled={submitting}
						className="self-start rounded bg-indigo-600 px-4 py-2 text-white disabled:opacity-50"
					>
						{submitting ? "作成中…" : "作成"}
					</button>
				</form>

				{created.length > 0 && (
					<div className="mb-10">
						<h2 className="mb-3 text-lg font-medium">
							このセッションで作成したURL
						</h2>
						<ul className="flex flex-col gap-2">
							{created.map((su) => (
								<li
									key={su.id}
									className="rounded border border-gray-200 p-3 text-sm dark:border-gray-700"
								>
									<a
										href={`${REDIRECT_BASE_URL}/${su.short_code}`}
										target="_blank"
										rel="noreferrer"
										className="font-mono text-indigo-600 underline"
									>
										{REDIRECT_BASE_URL}/{su.short_code}
									</a>
									<p className="truncate text-gray-500">→ {su.long_url}</p>
								</li>
							))}
						</ul>
					</div>
				)}

				<h2 className="mb-3 text-lg font-medium">IDで検索</h2>
				<form onSubmit={handleLookup} className="mb-4 flex gap-2">
					<input
						type="text"
						required
						value={lookupId}
						onChange={(e) => setLookupId(e.target.value)}
						placeholder="短縮URLのID(UUID)"
						className="flex-1 rounded border border-gray-300 px-3 py-2 font-mono text-sm dark:border-gray-600 dark:bg-gray-800"
					/>
					<button
						type="submit"
						className="rounded border border-gray-300 px-4 py-2 dark:border-gray-600"
					>
						検索
					</button>
				</form>
				{lookupError && <p className="text-sm text-red-600">{lookupError}</p>}
				{lookupResult && (
					<pre className="overflow-x-auto rounded bg-gray-100 p-4 text-xs dark:bg-gray-800">
						{JSON.stringify(lookupResult, null, 2)}
					</pre>
				)}
			</div>
		</div>
	);
}
