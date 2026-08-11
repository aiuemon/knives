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
import type { ShortURL, URLPermissionGrant } from "../api/types";
import { AuthProvider } from "../auth/AuthContext";
import { ShortURLPermissionsPage } from "./ShortURLPermissionsPage";

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

const viewerURL: ShortURL = {
	id: "url-2",
	short_code: "def456",
	long_url: "https://example.com/viewer-only",
	status: "active",
	created_at: "2026-01-02T00:00:00Z",
	your_role: "viewer",
	can_edit: false,
	can_delete: false,
	can_manage_permissions: false,
};

const existingGrant: URLPermissionGrant = {
	user_id: "editor-1",
	email: "editor@example.com",
	role: "editor",
	granted_at: "2026-01-01T00:00:00Z",
};

function jsonResponse(body: unknown, status = 200) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function renderPage(
	shortUrl: ShortURL,
	grants: URLPermissionGrant[],
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
			if (url.endsWith(`/api/short-urls/${shortUrl.id}/permissions`)) {
				if (init?.method === "POST") {
					const body = JSON.parse(init.body as string);
					return jsonResponse({
						user_id: "new-user",
						email: body.email,
						role: body.role,
						granted_at: "2026-01-02T00:00:00Z",
					});
				}
				return jsonResponse(grants);
			}
			if (url.endsWith(`/api/short-urls/${shortUrl.id}`)) {
				return jsonResponse(shortUrl);
			}
			return new Response(null, { status: 404 });
		}),
	);
	return render(
		<QueryClientProvider client={queryClient}>
			<MemoryRouter initialEntries={[`/short-urls/${shortUrl.id}/permissions`]}>
				<AuthProvider>
					<Routes>
						<Route
							path="/short-urls/:id/permissions"
							element={<ShortURLPermissionsPage />}
						/>
					</Routes>
				</AuthProvider>
			</MemoryRouter>
		</QueryClientProvider>,
	);
}

describe("ShortURLPermissionsPage", () => {
	afterEach(() => {
		cleanup();
		vi.unstubAllGlobals();
	});

	it("lists the users granted access", async () => {
		renderPage(ownedURL, [existingGrant]);
		const emailEl = await screen.findByText("editor@example.com");
		const row = emailEl.closest("li") as HTMLElement;
		expect(within(row).getByText("編集者")).toBeInTheDocument();
	});

	it("shows an owner-only notice instead of the management UI for a non-owner", async () => {
		renderPage(viewerURL, []);
		expect(await screen.findByText(/オーナーのみ行えます/)).toBeInTheDocument();
		expect(
			screen.queryByRole("button", { name: "招待" }),
		).not.toBeInTheDocument();
	});

	it("invites a new user", async () => {
		renderPage(ownedURL, []);
		await screen.findByRole("heading", { name: "ユーザーを招待" });

		const user = userEvent.setup();
		await user.type(
			screen.getByLabelText("メールアドレス"),
			"newperson@example.com",
		);
		await user.click(screen.getByRole("button", { name: "招待" }));

		await waitFor(() =>
			expect(screen.getByText("newperson@example.com")).toBeInTheDocument(),
		);
	});

	it("revokes a grant after confirmation", async () => {
		vi.spyOn(window, "confirm").mockReturnValue(true);
		renderPage(ownedURL, [existingGrant], (url, init) => {
			if (
				url.endsWith(`/api/short-urls/${ownedURL.id}/permissions/editor-1`) &&
				init?.method === "DELETE"
			) {
				return new Response(null, { status: 204 });
			}
			return undefined;
		});
		await screen.findByText("editor@example.com");

		const user = userEvent.setup();
		await user.click(screen.getByRole("button", { name: "削除" }));

		await waitFor(() =>
			expect(screen.queryByText("editor@example.com")).not.toBeInTheDocument(),
		);
	});

	it("shows a conflict error when revoking the last owner is refused", async () => {
		vi.spyOn(window, "confirm").mockReturnValue(true);
		const ownerGrant: URLPermissionGrant = {
			user_id: "owner-1",
			email: "owner@example.com",
			role: "owner",
			granted_at: "2026-01-01T00:00:00Z",
		};
		renderPage(ownedURL, [ownerGrant], (url, init) => {
			if (
				url.endsWith(`/api/short-urls/${ownedURL.id}/permissions/owner-1`) &&
				init?.method === "DELETE"
			) {
				return new Response("cannot remove the last remaining owner", {
					status: 409,
				});
			}
			return undefined;
		});
		await screen.findByRole("heading", { name: "権限を持つユーザー" });
		const grantsList = await screen.findByRole("list");
		await within(grantsList).findByText("owner@example.com");

		const user = userEvent.setup();
		await user.click(within(grantsList).getByRole("button", { name: "削除" }));

		expect(await screen.findByText(/last remaining owner/)).toBeInTheDocument();
		expect(
			within(grantsList).getByText("owner@example.com"),
		).toBeInTheDocument();
	});
});
