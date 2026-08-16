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
	// viewBoxは0〜100の固定座標系。preserveAspectRatio="none"でSVG自体を
	// 親要素(h-40)いっぱいに引き伸ばすので、CSSのパーセント高さのように
	// 親の実高さに依存しない。
	const xFor = (i: number) =>
		daily.length > 1 ? (i / (daily.length - 1)) * 100 : 50;
	const yFor = (count: number) => 100 - (count / maxDailyCount) * 100;

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
								aria-label="日別クリック数の折れ線グラフ"
								className="relative mb-8 h-40 border-b border-gray-200 dark:border-gray-700"
							>
								<svg
									viewBox="0 0 100 100"
									preserveAspectRatio="none"
									aria-hidden="true"
									className="absolute inset-0 h-full w-full overflow-visible"
								>
									<polyline
										points={daily
											.map((d, i) => `${xFor(i)},${yFor(d.click_count)}`)
											.join(" ")}
										fill="none"
										stroke="currentColor"
										strokeWidth="2"
										vectorEffect="non-scaling-stroke"
										className="text-indigo-500"
									/>
								</svg>
								{daily.map((d, i) => (
									// 点だけは非対称にスケールされるSVG座標系の外
									// (通常のHTML絶対配置)に置く。circleをviewBox
									// 内に置くと縦横で別々に引き伸ばされ、真円では
									// なく楕円になってしまうため。
									<div
										key={d.date}
										title={`${d.date}: ${d.click_count}件`}
										className="absolute h-2 w-2 -translate-x-1/2 -translate-y-1/2 rounded-full bg-indigo-500"
										style={{
											left: `${xFor(i)}%`,
											top: `${yFor(d.click_count)}%`,
										}}
									/>
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
