import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
	cleanup,
	render,
	screen,
	waitFor,
	within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ShortURL, ShortURLStats } from "../api/types";
import { AuthProvider } from "../auth/AuthContext";
import { ShortURLStatsPage } from "./ShortURLStatsPage";

const me = {
	id: "owner-1",
	email: "owner@example.com",
	is_system_admin: false,
};

const ownedURL: ShortURL = {
	id: "url-1",
	short_code: "abc123",
	long_url: "https://example.com/owned",
	status: "active",
	created_at: "2026-01-01T00:00:00Z",
	your_role: "owner",
	can_edit: true,
	can_delete: true,
	can_manage_permissions: true,
};

const statsWithData: ShortURLStats = {
	from: "2026-08-01",
	to: "2026-08-07",
	granularity: "day",
	daily: [
		{ date: "2026-08-01", click_count: 2 },
		{ date: "2026-08-02", click_count: 5 },
	],
	by_referrer: [
		{ referrer_host: "google.com", click_count: 5 },
		{ referrer_host: "", click_count: 2 },
	],
};

const emptyStats: ShortURLStats = {
	from: "2026-08-01",
	to: "2026-08-07",
	granularity: "day",
	daily: [],
	by_referrer: [],
};

const singleDayStats: ShortURLStats = {
	from: "2026-07-19",
	to: "2026-08-17",
	granularity: "day",
	daily: [{ date: "2026-08-08", click_count: 3 }],
	by_referrer: [{ referrer_host: "", click_count: 3 }],
};

const hourlyStats: ShortURLStats = {
	from: "2026-08-08",
	to: "2026-08-08",
	granularity: "hour",
	hourly: [
		{ hour: "2026-08-08T12:00:00.000Z", click_count: 2 },
		{ hour: "2026-08-08T14:00:00.000Z", click_count: 1 },
	],
	by_referrer: [{ referrer_host: "", click_count: 3 }],
};

function jsonResponse(body: unknown, status = 200) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function renderPage(
	stats: ShortURLStats,
	extraFetch?: (url: string, init?: RequestInit) => Response | undefined,
) {
	const queryClient = new QueryClient({
		defaultOptions: { queries: { retry: false } },
	});
	const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
		if (url.endsWith("/api/auth/me")) {
			return jsonResponse(me);
		}
		const custom = extraFetch?.(url, init);
		if (custom) {
			return custom;
		}
		if (url.includes(`/api/short-urls/${ownedURL.id}/stats`)) {
			return jsonResponse(stats);
		}
		if (url.endsWith(`/api/short-urls/${ownedURL.id}`)) {
			return jsonResponse(ownedURL);
		}
		return new Response(null, { status: 404 });
	});
	vi.stubGlobal("fetch", fetchMock);
	render(
		<QueryClientProvider client={queryClient}>
			<MemoryRouter initialEntries={[`/short-urls/${ownedURL.id}/stats`]}>
				<AuthProvider>
					<Routes>
						<Route
							path="/short-urls/:id/stats"
							element={<ShortURLStatsPage />}
						/>
					</Routes>
				</AuthProvider>
			</MemoryRouter>
		</QueryClientProvider>,
	);
	return fetchMock;
}

// 期間セレクタを「ユーザ設定」にしてfrom/toを固定日付にする。プリセット
// (デフォルトの「1ヶ月」等)は実行時の「今日」に依存するため、テストの
// 決定性を保つには明示的な範囲指定が必要。
async function setCustomRange(
	user: ReturnType<typeof userEvent.setup>,
	from: string,
	to: string,
) {
	await user.selectOptions(screen.getByLabelText("期間"), "ユーザ設定");
	const fromInput = screen.getByLabelText("開始日");
	const toInput = screen.getByLabelText("終了日");
	await user.clear(fromInput);
	await user.type(fromInput, from);
	await user.clear(toInput);
	await user.type(toInput, to);
}

describe("ShortURLStatsPage", () => {
	afterEach(() => {
		cleanup();
		vi.unstubAllGlobals();
	});

	it("shows the short URL header and referrer breakdown", async () => {
		renderPage(statsWithData);
		await screen.findByText(/abc123/);

		expect(screen.getByText("google.com")).toBeInTheDocument();
		expect(screen.getByText("(直接アクセス)")).toBeInTheDocument();
		expect(screen.getByText("7")).toBeInTheDocument(); // 期間合計クリック数 (2+5)
	});

	it("shows an empty-state message when there are no clicks in range", async () => {
		renderPage(emptyStats);
		await screen.findByText(/abc123/);

		expect(
			screen.getAllByText("この期間のクリックはありません。"),
		).toHaveLength(2);
	});

	it("zero-fills days without clicks so the line covers the full selected range", async () => {
		const user = userEvent.setup();
		renderPage(statsWithData);
		await screen.findByText(/abc123/);

		// 2026-08-01〜2026-08-07は7日間。click_stats_dailyはクリックの
		// あった日のみ行を持つが(daily.lengthは2)、グラフは範囲内の
		// 全日付を0件埋めして描画するため、点は7個描画される。
		await setCustomRange(user, statsWithData.from, statsWithData.to);

		const chart = screen.getByRole("img", {
			name: "日別クリック数の折れ線グラフ",
		});
		await waitFor(() =>
			expect(chart.querySelectorAll(".rounded-full")).toHaveLength(7),
		);
		const titles = Array.from(chart.querySelectorAll(".rounded-full")).map(
			(el) => el.getAttribute("title"),
		);
		expect(titles).toContain("2026-08-01: 2件");
		expect(titles).toContain("2026-08-02: 5件");
		expect(titles).toContain("2026-08-03: 0件"); // クリックの無い日は0件埋め
	});

	it("renders a single visible point when the range has only one day of clicks", async () => {
		// 元の不具合(#31)の再現条件: 期間内の日別データが1件のみでも、
		// クリック数が0にならず見える形で描画されること。点はSVGの
		// viewBox外(通常のHTML絶対配置)に置いているため、非対称な
		// スケーリングで楕円になることもない(#33/#35のフォローアップ)。
		const user = userEvent.setup();
		renderPage(singleDayStats);
		await screen.findByText(/abc123/);

		await setCustomRange(user, singleDayStats.from, singleDayStats.to);

		const chart = screen.getByRole("img", {
			name: "日別クリック数の折れ線グラフ",
		});
		await waitFor(() => {
			const titles = Array.from(chart.querySelectorAll(".rounded-full")).map(
				(el) => el.getAttribute("title"),
			);
			expect(titles).toContain("2026-08-08: 3件");
		});
	});

	it("shows Y-axis and X-axis labels next to the chart", async () => {
		const user = userEvent.setup();
		renderPage(statsWithData);
		await screen.findByText(/abc123/);

		await setCustomRange(user, statsWithData.from, statsWithData.to);

		const chart = await screen.findByRole("img", {
			name: "日別クリック数の折れ線グラフ",
		});
		const chartArea = chart.parentElement as HTMLElement;

		// Y軸: 最大値(5)と最小値(0)
		await waitFor(() =>
			expect(within(chartArea).getByText("5")).toBeInTheDocument(),
		);
		expect(within(chartArea).getByText("0")).toBeInTheDocument();

		// X軸: 範囲の開始日・終了日のラベル(MM-DD表記)
		expect(within(chartArea).getByText("08-01")).toBeInTheDocument();
		expect(within(chartArea).getByText("08-07")).toBeInTheDocument();
	});

	it("changes the requested range when a preset is selected", async () => {
		const fetchMock = renderPage(statsWithData);
		await screen.findByText(/abc123/);

		const user = userEvent.setup();
		await user.selectOptions(screen.getByLabelText("期間"), "1週間");

		const expectedFrom = (() => {
			const d = new Date();
			d.setDate(d.getDate() - 6);
			return d.toISOString().slice(0, 10);
		})();

		await waitFor(() =>
			expect(
				fetchMock.mock.calls.some(([url]) =>
					String(url).includes(`from=${expectedFrom}`),
				),
			).toBe(true),
		);
	});

	it("uses the short URL's creation date as the start when 全期間 is selected", async () => {
		const fetchMock = renderPage(statsWithData);
		await screen.findByText(/abc123/);

		const user = userEvent.setup();
		await user.selectOptions(screen.getByLabelText("期間"), "全期間");

		const createdDate = ownedURL.created_at.slice(0, 10);
		await waitFor(() =>
			expect(
				fetchMock.mock.calls.some(([url]) =>
					String(url).includes(`from=${createdDate}`),
				),
			).toBe(true),
		);
	});

	it("switches to hourly granularity and zero-fills empty hours when the checkbox is checked", async () => {
		const user = userEvent.setup();
		const fetchMock = renderPage(statsWithData, (url) => {
			if (url.includes("granularity=hour")) {
				return jsonResponse(hourlyStats);
			}
			return undefined;
		});
		await screen.findByText(/abc123/);

		await setCustomRange(user, hourlyStats.from, hourlyStats.to);
		await user.click(screen.getByLabelText("1時間単位で表示"));

		await waitFor(() =>
			expect(
				fetchMock.mock.calls.some(([url]) =>
					String(url).includes("granularity=hour"),
				),
			).toBe(true),
		);

		const chart = await screen.findByRole("img", {
			name: "時間別クリック数の折れ線グラフ",
		});
		await waitFor(() =>
			expect(chart.querySelectorAll(".rounded-full")).toHaveLength(24),
		);
		const titles = Array.from(chart.querySelectorAll(".rounded-full")).map(
			(el) => el.getAttribute("title"),
		);
		expect(titles).toContain("08-08 12:00: 2件");
		expect(titles).toContain("08-08 14:00: 1件");
		expect(titles).toContain("08-08 13:00: 0件"); // クリックの無い時間は0件埋め
	});

	it("refetches stats when the custom date range changes", async () => {
		const fetchMock = renderPage(statsWithData);
		await screen.findByText(/abc123/);

		const user = userEvent.setup();
		await user.selectOptions(screen.getByLabelText("期間"), "ユーザ設定");

		const fromInput = screen.getByLabelText("開始日") as HTMLInputElement;
		await user.clear(fromInput);
		await user.type(fromInput, "2026-07-01");

		await waitFor(() =>
			expect(
				fetchMock.mock.calls.some(([url]) =>
					String(url).includes("from=2026-07-01"),
				),
			).toBe(true),
		);
	});
});
