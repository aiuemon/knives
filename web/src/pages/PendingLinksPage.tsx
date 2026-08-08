import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError, api } from "../api/client";
import type { PendingLink } from "../api/types";
import { Header } from "../components/Header";

export function PendingLinksPage() {
	const queryClient = useQueryClient();
	const [error, setError] = useState<string | null>(null);
	const [approvingId, setApprovingId] = useState<string | null>(null);

	const query = useQuery({
		queryKey: ["pending-links"],
		queryFn: () => api.get<PendingLink[]>("/auth/pending-links"),
	});

	async function handleApprove(id: string) {
		setError(null);
		setApprovingId(id);
		try {
			await api.post(`/auth/pending-links/${id}/approve`);
			await queryClient.invalidateQueries({ queryKey: ["pending-links"] });
		} catch (err) {
			setError(err instanceof ApiError ? err.message : "承認に失敗しました");
		} finally {
			setApprovingId(null);
		}
	}

	return (
		<div>
			<Header />
			<div className="mx-auto max-w-2xl px-4 py-8">
				<h1 className="mb-2 text-2xl font-semibold">保留中の統合リクエスト</h1>
				<p className="mb-6 text-sm text-gray-600 dark:text-gray-300">
					あなたのアカウントに新しいログイン方法を追加しようとしたリクエストです。心当たりがあるものだけ承認してください。
				</p>
				{query.isLoading && <p>読み込み中…</p>}
				{error && <p className="mb-4 text-sm text-red-600">{error}</p>}
				{query.data && query.data.length === 0 && (
					<p className="text-gray-500">保留中のリクエストはありません。</p>
				)}
				<ul className="flex flex-col gap-3">
					{query.data?.map((p) => (
						<li
							key={p.id}
							className="flex items-center justify-between rounded border border-gray-200 p-4 dark:border-gray-700"
						>
							<div>
								<p className="font-medium">{p.provider_type}</p>
								<p className="text-xs text-gray-500">
									期限: {new Date(p.expires_at).toLocaleString()}
								</p>
							</div>
							<button
								type="button"
								disabled={approvingId === p.id}
								onClick={() => handleApprove(p.id)}
								className="rounded bg-indigo-600 px-3 py-1.5 text-sm text-white disabled:opacity-50"
							>
								承認
							</button>
						</li>
					))}
				</ul>
			</div>
		</div>
	);
}
