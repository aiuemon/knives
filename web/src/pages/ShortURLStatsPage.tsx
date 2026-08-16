import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import type { ShortURL, ShortURLStats } from "../api/types";
import { Header } from "../components/Header";

// internal/stats.maxRangeDaysと合わせる。これを超える範囲を
// リクエストするとAPIが400を返す。
const STATS_MAX_RANGE_DAYS = 366;

type RangeMode = "1d" | "7d" | "30d" | "365d" | "all" | "custom";
type PresetRangeMode = Exclude<RangeMode, "custom">;

function todayISO() {
	return new Date().toISOString().slice(0, 10);
}

function daysAgoISO(days: number) {
	const d = new Date();
	d.setDate(d.getDate() - days);
	return d.toISOString().slice(0, 10);
}

// [fromISO, toISO]に含まれる日付を1日刻みで列挙する。UTC基準で計算し、
// ローカルタイムゾーンによるsetDate/toISOStringのズレを避ける。
function enumerateDates(fromISO: string, toISO: string): string[] {
	const dates: string[] = [];
	const cur = new Date(`${fromISO}T00:00:00Z`);
	const end = new Date(`${toISO}T00:00:00Z`);
	while (cur.getTime() <= end.getTime()) {
		dates.push(cur.toISOString().slice(0, 10));
		cur.setUTCDate(cur.getUTCDate() + 1);
	}
	return dates;
}

function computeFromDate(
	mode: PresetRangeMode,
	createdDate: string | undefined,
): string {
	switch (mode) {
		case "1d":
			return todayISO();
		case "7d":
			return daysAgoISO(6);
		case "30d":
			return daysAgoISO(29);
		case "365d":
			return daysAgoISO(364);
		case "all": {
			const earliestAllowed = daysAgoISO(STATS_MAX_RANGE_DAYS - 1);
			return createdDate && createdDate > earliestAllowed
				? createdDate
				: earliestAllowed;
		}
	}
}

export function ShortURLStatsPage() {
	const { id } = useParams<{ id: string }>();
	const [rangeMode, setRangeMode] = useState<RangeMode>("30d");
	const [customFrom, setCustomFrom] = useState(daysAgoISO(29));
	const [customTo, setCustomTo] = useState(todayISO());

	const urlQuery = useQuery({
		queryKey: ["short-urls", id],
		queryFn: () => api.get<ShortURL>(`/short-urls/${id}`),
		enabled: !!id,
	});

	const createdDate = urlQuery.data?.created_at.slice(0, 10);
	const to = rangeMode === "custom" ? customTo : todayISO();
	const from =
		rangeMode === "custom"
			? customFrom
			: computeFromDate(rangeMode, createdDate);

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

	// click_stats_dailyはクリックのあった日のみ行を持つため、daily配列は
	// 範囲内の日付を飛び飛びにしか含まない。横軸を実際の日付間隔と
	// 対応させるため、範囲内の全日付を0件埋めしたseriesを作る。
	const series =
		daily.length > 0
			? enumerateDates(from, to).map((date) => ({
					date,
					click_count: daily.find((d) => d.date === date)?.click_count ?? 0,
				}))
			: [];

	// viewBoxは0〜100の固定座標系。preserveAspectRatio="none"でSVG自体を
	// 親要素(h-40)いっぱいに引き伸ばすので、CSSのパーセント高さのように
	// 親の実高さに依存しない。
	const xFor = (i: number) =>
		series.length > 1 ? (i / (series.length - 1)) * 100 : 50;
	const yFor = (count: number) => 100 - (count / maxDailyCount) * 100;

	const tickCount = Math.min(6, series.length);
	const tickIndices = Array.from(
		new Set(
			Array.from({ length: tickCount }, (_, i) =>
				tickCount > 1
					? Math.round((i * (series.length - 1)) / (tickCount - 1))
					: 0,
			),
		),
	);

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
						期間
						<select
							value={rangeMode}
							onChange={(e) => setRangeMode(e.target.value as RangeMode)}
							className="rounded border border-gray-300 px-3 py-1.5 dark:border-gray-600 dark:bg-gray-800"
						>
							<option value="1d">1日</option>
							<option value="7d">1週間</option>
							<option value="30d">1ヶ月</option>
							<option value="365d">1年</option>
							<option value="all">全期間</option>
							<option value="custom">ユーザ設定</option>
						</select>
					</label>
					{rangeMode === "custom" && (
						<>
							<label className="flex flex-col gap-1 text-sm text-gray-600 dark:text-gray-300">
								開始日
								<input
									type="date"
									value={customFrom}
									max={customTo}
									onChange={(e) => setCustomFrom(e.target.value)}
									className="rounded border border-gray-300 px-3 py-1.5 dark:border-gray-600 dark:bg-gray-800"
								/>
							</label>
							<label className="flex flex-col gap-1 text-sm text-gray-600 dark:text-gray-300">
								終了日
								<input
									type="date"
									value={customTo}
									min={customFrom}
									max={todayISO()}
									onChange={(e) => setCustomTo(e.target.value)}
									className="rounded border border-gray-300 px-3 py-1.5 dark:border-gray-600 dark:bg-gray-800"
								/>
							</label>
						</>
					)}
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
							<span className="ml-2 text-gray-400">
								({from} 〜 {to})
							</span>
						</p>

						<h2 className="mb-3 text-lg font-medium">日別クリック数</h2>
						{daily.length === 0 ? (
							<p className="mb-8 text-gray-500">
								この期間のクリックはありません。
							</p>
						) : (
							<div className="mb-8 grid grid-cols-[auto_1fr] gap-x-2">
								<div
									aria-hidden="true"
									className="flex h-40 flex-col justify-between text-right text-xs text-gray-400"
								>
									<span>{maxDailyCount}</span>
									<span>{Math.round(maxDailyCount / 2)}</span>
									<span>0</span>
								</div>
								<div
									role="img"
									aria-label="日別クリック数の折れ線グラフ"
									className="relative h-40 border-b border-gray-200 dark:border-gray-700"
								>
									<svg
										viewBox="0 0 100 100"
										preserveAspectRatio="none"
										aria-hidden="true"
										className="absolute inset-0 h-full w-full overflow-visible"
									>
										<polyline
											points={series
												.map((d, i) => `${xFor(i)},${yFor(d.click_count)}`)
												.join(" ")}
											fill="none"
											stroke="currentColor"
											strokeWidth="2"
											vectorEffect="non-scaling-stroke"
											className="text-indigo-500"
										/>
									</svg>
									{series.map((d, i) => (
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
								<div />
								<div
									aria-hidden="true"
									className="relative h-4 text-xs text-gray-400"
								>
									{tickIndices.map((i) => (
										<span
											key={series[i]?.date}
											className="absolute -translate-x-1/2"
											style={{ left: `${xFor(i)}%` }}
										>
											{series[i]?.date.slice(5)}
										</span>
									))}
								</div>
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
