import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import type { ShortURL, ShortURLStats } from "../api/types";
import { Header } from "../components/Header";

function todayISO() {
	return new Date().toISOString().slice(0, 10);
}

function daysAgoISO(days: number) {
	const d = new Date();
	d.setDate(d.getDate() - days);
	return d.toISOString().slice(0, 10);
}

export function ShortURLStatsPage() {
	const { id } = useParams<{ id: string }>();
	const [from, setFrom] = useState(daysAgoISO(29));
	const [to, setTo] = useState(todayISO());

	const urlQuery = useQuery({
		queryKey: ["short-urls", id],
		queryFn: () => api.get<ShortURL>(`/short-urls/${id}`),
		enabled: !!id,
	});

	const statsQuery = useQuery({
		queryKey: ["short-urls", id, "stats", { from, to }],
		queryFn: () =>
			api.get<ShortURLStats>(`/short-urls/${id}/stats?from=${from}&to=${to}`),
		enabled: !!id,
	});

	const daily = statsQuery.data?.daily ?? [];
	const byReferrer = statsQuery.data?.by_referrer ?? [];
	const totalClicks = daily.reduce((sum, d) => sum + d.click_count, 0);
	const maxDailyCount = Math.max(1, ...daily.map((d) => d.click_count));

	return (
		<div>
			<Header />
			<div className="mx-auto max-w-3xl px-4 py-8">
				<Link
					to="/"
					className="mb-4 inline-block text-sm text-indigo-600 hover:underline"
				>
					← 短縮URL一覧に戻る
				</Link>
				<h1 className="mb-2 text-2xl font-semibold">アクセス統計</h1>

				{urlQuery.isLoading && <p>読み込み中…</p>}
				{urlQuery.isError && (
					<p className="text-sm text-red-600">短縮URLの取得に失敗しました</p>
				)}
				{urlQuery.data && (
					<p className="mb-6 truncate text-sm text-gray-500">
						{urlQuery.data.short_code} → {urlQuery.data.long_url}
					</p>
				)}

				<div className="mb-6 flex flex-wrap items-end gap-4">
					<label className="flex flex-col gap-1 text-sm text-gray-600 dark:text-gray-300">
						開始日
						<input
							type="date"
							value={from}
							max={to}
							onChange={(e) => setFrom(e.target.value)}
							className="rounded border border-gray-300 px-3 py-1.5 dark:border-gray-600 dark:bg-gray-800"
						/>
					</label>
					<label className="flex flex-col gap-1 text-sm text-gray-600 dark:text-gray-300">
						終了日
						<input
							type="date"
							value={to}
							min={from}
							max={todayISO()}
							onChange={(e) => setTo(e.target.value)}
							className="rounded border border-gray-300 px-3 py-1.5 dark:border-gray-600 dark:bg-gray-800"
						/>
					</label>
				</div>

				{statsQuery.isLoading && <p>読み込み中…</p>}
				{statsQuery.isError && (
					<p className="text-sm text-red-600">統計の取得に失敗しました</p>
				)}

				{statsQuery.data && (
					<>
						<p className="mb-4 text-sm text-gray-600 dark:text-gray-300">
							期間合計クリック数:{" "}
							<span className="font-semibold">{totalClicks}</span>
						</p>

						<h2 className="mb-3 text-lg font-medium">日別クリック数</h2>
						{daily.length === 0 ? (
							<p className="mb-8 text-gray-500">
								この期間のクリックはありません。
							</p>
						) : (
							<div
								role="img"
								aria-label="日別クリック数の棒グラフ"
								className="mb-8 flex h-40 gap-1 border-b border-gray-200 dark:border-gray-700"
							>
								{daily.map((d) => (
									<div
										key={d.date}
										title={`${d.date}: ${d.click_count}件`}
										className="flex flex-1 flex-col items-center justify-end"
									>
										<div
											className="w-full rounded-t bg-indigo-500"
											style={{
												height: `${(d.click_count / maxDailyCount) * 100}%`,
												minHeight: d.click_count > 0 ? "2px" : "0",
											}}
										/>
									</div>
								))}
							</div>
						)}

						<h2 className="mb-3 text-lg font-medium">参照元別クリック数</h2>
						{byReferrer.length === 0 ? (
							<p className="text-gray-500">この期間のクリックはありません。</p>
						) : (
							<table className="w-full text-left text-sm">
								<thead>
									<tr className="border-b border-gray-200 text-gray-500 dark:border-gray-700 dark:text-gray-400">
										<th className="py-2 pr-4 font-medium">参照元</th>
										<th className="py-2 pr-4 font-medium">クリック数</th>
									</tr>
								</thead>
								<tbody>
									{byReferrer.map((r) => (
										<tr
											key={r.referrer_host || "(direct)"}
											className="border-b border-gray-100 dark:border-gray-800"
										>
											<td className="py-2 pr-4">
												{r.referrer_host || "(直接アクセス)"}
											</td>
											<td className="py-2 pr-4">{r.click_count}</td>
										</tr>
									))}
								</tbody>
							</table>
						)}
					</>
				)}
			</div>
		</div>
	);
}
