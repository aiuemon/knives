import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ShortURLListItem, ShortURLListResponse } from "../api/types";
import { AuthProvider } from "../auth/AuthContext";
import { DashboardPage } from "./DashboardPage";

const regularUser = {
	id: "user-1",
	email: "user@example.com",
	is_system_admin: false,
};
const adminUser = {
	id: "admin-1",
	email: "admin@example.com",
	is_system_admin: true,
};

const ownedURL: ShortURLListItem = {
	id: "url-1",
	short_code: "abc123",
	long_url: "https://example.com/owned",
	status: "active",
	created_at: "2026-01-01T00:00:00Z",
	your_role: "owner",
	can_edit: true,
	can_delete: true,
	can_manage_permissions: true,
	click_count: 3,
};

const viewOnlyURL: ShortURLListItem = {
	id: "url-2",
	short_code: "def456",
	long_url: "https://example.com/view-only",
	status: "active",
	created_at: "2026-01-02T00:00:00Z",
	your_role: "",
	can_edit: false,
	can_delete: false,
	can_manage_permissions: false,
	click_count: 0,
};

function jsonResponse(body: unknown, status = 200) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function renderPage(
	me: typeof regularUser,
	shortUrls: ShortURLListItem[],
	extraFetch?: (url: string, init?: RequestInit) => Response | undefined,
) {
	const queryClient = new QueryClient({
		defaultOptions: { queries: { retry: false } },
	});
	vi.stubGlobal(
		"fetch",
		vi.fn(async (url: string, init?: RequestInit) => {
			if (url.endsWith("/api/auth/me")) {
				return jsonResponse(me);
			}
			const custom = extraFetch?.(url, init);
			if (custom) {
				return custom;
			}
			if (
				url.includes("/api/short-urls") &&
				(!init || init.method === undefined)
			) {
				const resp: ShortURLListResponse = {
					items: shortUrls,
					total: shortUrls.length,
				};
				return jsonResponse(resp);
			}
			if (url.endsWith("/api/short-urls") && init?.method === "POST") {
				const body = JSON.parse(init.body as string);
				return jsonResponse(
					{
						id: "url-new",
						short_code: "newcode",
						long_url: body.long_url,
						status: "active",
						created_at: "2026-01-03T00:00:00Z",
						your_role: "owner",
						can_edit: true,
						can_delete: true,
						can_manage_permissions: true,
					},
					201,
				);
			}
			return new Response(null, { status: 404 });
		}),
	);
	return render(
		<QueryClientProvider client={queryClient}>
			<MemoryRouter>
				<AuthProvider>
					<DashboardPage />
				</AuthProvider>
			</MemoryRouter>
		</QueryClientProvider>,
	);
}

describe("DashboardPage", () => {
	afterEach(() => {
		cleanup();
		vi.unstubAllGlobals();
	});

	it("lists the user's short URLs", async () => {
		renderPage(regularUser, [ownedURL]);
		expect(await screen.findByText(/abc123/)).toBeInTheDocument();
		expect(screen.getByText("https://example.com/owned")).toBeInTheDocument();
	});

	it("always shows a stats link, regardless of edit/delete permissions", async () => {
		renderPage(regularUser, [viewOnlyURL]);
		await screen.findByText(/def456/);
		expect(screen.getByRole("link", { name: "統計" })).toHaveAttribute(
			"href",
			`/short-urls/${viewOnlyURL.id}/stats`,
		);
	});

	it("only shows edit/delete/permissions actions the user is allowed to take", async () => {
		renderPage(regularUser, [viewOnlyURL]);
		await screen.findByText(/def456/);

		expect(
			screen.queryByRole("button", { name: "編集" }),
		).not.toBeInTheDocument();
		expect(
			screen.queryByRole("button", { name: "削除" }),
		).not.toBeInTheDocument();
		expect(
			screen.queryByRole("link", { name: "権限管理" }),
		).not.toBeInTheDocument();
		expect(screen.getByText(/閲覧のみ/)).toBeInTheDocument();
	});

	it("shows the scope toggle only for system_admin", async () => {
		renderPage(regularUser, [ownedURL]);
		await screen.findByText(/abc123/);
		expect(screen.queryByText("自分のURLのみ表示")).not.toBeInTheDocument();

		cleanup();
		renderPage(adminUser, [ownedURL]);
		await screen.findByText(/abc123/);
		expect(screen.getByText("自分のURLのみ表示")).toBeInTheDocument();
	});

	it("shows the creator email column only for system_admin", async () => {
		renderPage(regularUser, [
			{ ...ownedURL, creator_email: "owner@example.com" },
		]);
		await screen.findByText(/abc123/);
		expect(screen.queryByText("owner@example.com")).not.toBeInTheDocument();

		cleanup();
		renderPage(adminUser, [
			{ ...ownedURL, creator_email: "owner@example.com" },
		]);
		await screen.findByText(/abc123/);
		expect(screen.getByText("owner@example.com")).toBeInTheDocument();
	});

	it("submits the create form and prepends the result to the list", async () => {
		renderPage(regularUser, []);
		await screen.findByRole("heading", { name: "短縮URLを作成" });

		const user = userEvent.setup();
		await user.type(
			screen.getByLabelText("遷移先URL"),
			"https://example.com/new-page",
		);
		await user.click(screen.getByRole("button", { name: "作成" }));

		await waitFor(() =>
			expect(screen.getByText(/newcode/)).toBeInTheDocument(),
		);
	});

	it("edits a URL via the inline edit form", async () => {
		renderPage(regularUser, [ownedURL], (url, init) => {
			if (url.endsWith("/api/short-urls/url-1") && init?.method === "PATCH") {
				const body = JSON.parse(init.body as string);
				return jsonResponse({ ...ownedURL, long_url: body.long_url });
			}
			return undefined;
		});
		await screen.findByText(/abc123/);

		const user = userEvent.setup();
		await user.click(screen.getByRole("button", { name: "編集" }));

		// 編集フォームが開くと「遷移先URL」ラベルの入力欄が
		// (作成フォーム分と合わせて)2つになるため、後者(編集フォーム側)を使う。
		const inputs = (await screen.findAllByLabelText(
			"遷移先URL",
		)) as HTMLInputElement[];
		const editInput = inputs[inputs.length - 1];
		await user.clear(editInput);
		await user.type(editInput, "https://example.com/updated");
		await user.click(screen.getByRole("button", { name: "更新" }));

		await waitFor(() =>
			expect(
				screen.getByText("https://example.com/updated"),
			).toBeInTheDocument(),
		);
	});

	it("deletes a URL after confirmation", async () => {
		vi.spyOn(window, "confirm").mockReturnValue(true);
		renderPage(regularUser, [ownedURL], (url, init) => {
			if (url.endsWith("/api/short-urls/url-1") && init?.method === "DELETE") {
				return new Response(null, { status: 204 });
			}
			return undefined;
		});
		await screen.findByText(/abc123/);

		const user = userEvent.setup();
		await user.click(screen.getByRole("button", { name: "削除" }));

		await waitFor(() =>
			expect(screen.queryByText(/abc123/)).not.toBeInTheDocument(),
		);
	});

	it("toggles sort direction when a column header is clicked", async () => {
		renderPage(regularUser, [ownedURL]);
		await screen.findByText(/abc123/);

		const user = userEvent.setup();
		await user.click(screen.getByRole("button", { name: "クリック数" }));

		await waitFor(() =>
			expect(
				screen.getByRole("button", { name: /クリック数/ }),
			).toHaveTextContent("▲"),
		);
	});
});
