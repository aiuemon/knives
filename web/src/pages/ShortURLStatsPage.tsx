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

type ChartPoint = {
	key: string;
	// title: ホバー時のツールチップ用(省略しない完全な表記)。
	// tick: 横軸ラベル用(スペースが限られるため簡略表記)。
	title: string;
	tick: string;
	click_count: number;
};

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

// [fromISO, toISO]に含まれる時刻を1時間刻みで列挙する(fromの0時からtoの
// 翌日0時の直前まで、UTC基準)。バックエンド(FindHourlyClickCounts)も
// セッションのTimeZoneに依らずUTC境界で丸めているため、同じ基準で揃える。
function enumerateHours(fromISO: string, toISO: string): string[] {
	const hours: string[] = [];
	const cur = new Date(`${fromISO}T00:00:00Z`);
	const end = new Date(`${toISO}T00:00:00Z`);
	end.setUTCDate(end.getUTCDate() + 1);
	while (cur.getTime() < end.getTime()) {
		hours.push(cur.toISOString());
		cur.setUTCHours(cur.getUTCHours() + 1);
	}
	return hours;
}

// "2026-08-08T21:00:00.000Z" → "08-08 21:00"(UTC基準の表示に統一)
function formatHourLabel(iso: string): string {
	const d = new Date(iso);
	const mm = String(d.getUTCMonth() + 1).padStart(2, "0");
	const dd = String(d.getUTCDate()).padStart(2, "0");
	const hh = String(d.getUTCHours()).padStart(2, "0");
	return `${mm}-${dd} ${hh}:00`;
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
	const [hourlyView, setHourlyView] = useState(false);

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
		queryKey: ["short-urls", id, "stats", { from, to, hourlyView }],
		queryFn: () =>
			api.get<ShortURLStats>(
				`/short-urls/${id}/stats?from=${from}&to=${to}${
					hourlyView ? "&granularity=hour" : ""
				}`,
			),
		enabled: !!id,
	});

	const dailyData = statsQuery.data?.daily ?? [];
	const hourlyData = statsQuery.data?.hourly ?? [];
	const activePoints = hourlyView ? hourlyData : dailyData;
	const byReferrer = statsQuery.data?.by_referrer ?? [];
	const totalClicks = activePoints.reduce((sum, p) => sum + p.click_count, 0);
	const maxCount = Math.max(1, ...activePoints.map((p) => p.click_count));

	// click_stats_daily/click_eventsはクリックのあった日・時間のみ行を
	// 持つため、activePointsは範囲内を飛び飛びにしか含まない。横軸を
	// 実際の日付・時刻間隔と対応させるため、範囲内の全区間を0件埋めした
	// seriesを作る。
	const dailyByDate = new Map(dailyData.map((d) => [d.date, d.click_count]));
	const hourlyByKey = new Map(
		hourlyData.map((h) => [new Date(h.hour).toISOString(), h.click_count]),
	);
	const series: ChartPoint[] =
		activePoints.length === 0
			? []
			: hourlyView
				? enumerateHours(from, to).map((iso) => {
						const label = formatHourLabel(iso);
						return {
							key: iso,
							title: label,
							tick: label,
							click_count: hourlyByKey.get(iso) ?? 0,
						};
					})
				: enumerateDates(from, to).map((date) => ({
						key: date,
						title: date,
						tick: date.slice(5),
						click_count: dailyByDate.get(date) ?? 0,
					}));

	// viewBoxは0〜100の固定座標系。preserveAspectRatio="none"でSVG自体を
	// 親要素(h-40)いっぱいに引き伸ばすので、CSSのパーセント高さのように
	// 親の実高さに依存しない。
	const xFor = (i: number) =>
		series.length > 1 ? (i / (series.length - 1)) * 100 : 50;
	const yFor = (count: number) => 100 - (count / maxCount) * 100;

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

	const chartHeading = hourlyView ? "時間別クリック数" : "日別クリック数";
	const chartAriaLabel = hourlyView
		? "時間別クリック数の折れ線グラフ"
		: "日別クリック数の折れ線グラフ";

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
					<label className="flex items-center gap-2 pb-1.5 text-sm text-gray-600 dark:text-gray-300">
						<input
							type="checkbox"
							checked={hourlyView}
							onChange={(e) => setHourlyView(e.target.checked)}
						/>
						1時間単位で表示
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
							<span className="ml-2 text-gray-400">
								({from} 〜 {to})
							</span>
						</p>

						<h2 className="mb-3 text-lg font-medium">{chartHeading}</h2>
						{activePoints.length === 0 ? (
							<p className="mb-8 text-gray-500">
								この期間のクリックはありません。
							</p>
						) : (
							<div className="mb-8 grid grid-cols-[auto_1fr] gap-x-2">
								<div
									aria-hidden="true"
									className="flex h-40 flex-col justify-between text-right text-xs text-gray-400"
								>
									<span>{maxCount}</span>
									<span>{Math.round(maxCount / 2)}</span>
									<span>0</span>
								</div>
								<div
									role="img"
									aria-label={chartAriaLabel}
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
											key={d.key}
											title={`${d.title}: ${d.click_count}件`}
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
											key={series[i]?.key}
											className="absolute -translate-x-1/2"
											style={{ left: `${xFor(i)}%` }}
										>
											{series[i]?.tick}
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
