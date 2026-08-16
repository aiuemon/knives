import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
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
	daily: [],
	by_referrer: [],
};

const singleDayStats: ShortURLStats = {
	from: "2026-07-19",
	to: "2026-08-17",
	daily: [{ date: "2026-08-08", click_count: 3 }],
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

	it("renders one point per day on the line chart", async () => {
		renderPage(statsWithData);
		await screen.findByText(/abc123/);

		const chart = screen.getByRole("img", {
			name: "日別クリック数の折れ線グラフ",
		});
		expect(chart.querySelectorAll("circle")).toHaveLength(
			statsWithData.daily.length,
		);
	});

	it("renders a single visible point when the range has only one day of clicks", async () => {
		// 元の不具合(#31)の再現条件: 期間内の日別データが1件のみでも、
		// クリック数が0にならず見える形で描画されること。
		renderPage(singleDayStats);
		await screen.findByText(/abc123/);

		const chart = screen.getByRole("img", {
			name: "日別クリック数の折れ線グラフ",
		});
		const circles = chart.querySelectorAll("circle");
		expect(circles).toHaveLength(1);
		expect(circles[0]?.querySelector("title")?.textContent).toBe(
			"2026-08-08: 3件",
		);
	});

	it("refetches stats when the date range changes", async () => {
		const fetchMock = renderPage(statsWithData);
		await screen.findByText(/abc123/);

		const user = userEvent.setup();
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
