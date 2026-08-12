import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
	cleanup,
	render,
	screen,
	waitFor,
	within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AdminUser } from "../api/types";
import { AuthProvider } from "../auth/AuthContext";
import { AdminUsersPage } from "./AdminUsersPage";

const me = { id: "admin-1", email: "admin@example.com", is_system_admin: true };
const users: AdminUser[] = [
	{
		id: "admin-1",
		email: "admin@example.com",
		email_verified: true,
		is_system_admin: true,
		status: "active",
		created_at: "2026-01-01T00:00:00Z",
	},
	{
		id: "user-2",
		email: "someone@example.com",
		email_verified: true,
		is_system_admin: false,
		status: "active",
		created_at: "2026-01-02T00:00:00Z",
	},
];

function jsonResponse(body: unknown, status = 200) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function renderPage() {
	const queryClient = new QueryClient({
		defaultOptions: { queries: { retry: false } },
	});
	return render(
		<QueryClientProvider client={queryClient}>
			<MemoryRouter>
				<AuthProvider>
					<AdminUsersPage />
				</AuthProvider>
			</MemoryRouter>
		</QueryClientProvider>,
	);
}

function rowFor(email: string) {
	const rows = screen.getAllByRole("row");
	return rows.find((r) => within(r).queryByText(email)) as HTMLElement;
}

describe("AdminUsersPage", () => {
	beforeEach(() => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async (url: string, init?: RequestInit) => {
				if (url.endsWith("/api/auth/me")) {
					return jsonResponse(me);
				}
				if (url.endsWith("/api/admin/users")) {
					return jsonResponse(users);
				}
				const patchMatch = url.match(/\/api\/admin\/users\/(.+)$/);
				if (patchMatch && init?.method === "PATCH") {
					const id = patchMatch[1];
					const target = users.find((u) => u.id === id);
					const body = JSON.parse(init.body as string);
					return jsonResponse({ ...target, ...body });
				}
				return new Response(null, { status: 404 });
			}),
		);
	});

	afterEach(() => {
		cleanup();
		vi.unstubAllGlobals();
	});

	it("lists every user with their role and status", async () => {
		renderPage();
		expect(await screen.findByText("admin@example.com")).toBeInTheDocument();
		expect(screen.getByText("someone@example.com")).toBeInTheDocument();
	});

	it("shows 管理者/無効 checkboxes reflecting each user's current state", async () => {
		renderPage();
		await screen.findByText("admin@example.com");

		const selfRow = rowFor("admin@example.com");
		expect(
			within(selfRow).getByRole("checkbox", { name: "管理者" }),
		).toBeChecked();
		expect(
			within(selfRow).getByRole("checkbox", { name: "無効" }),
		).not.toBeChecked();

		const otherRow = rowFor("someone@example.com");
		expect(
			within(otherRow).getByRole("checkbox", { name: "管理者" }),
		).not.toBeChecked();
	});

	it("disables revoking the caller's own system_admin status", async () => {
		renderPage();
		await screen.findByText("admin@example.com");

		const selfRow = rowFor("admin@example.com");
		const adminCheckbox = within(selfRow).getByRole("checkbox", {
			name: "管理者",
		});
		expect(adminCheckbox).toBeDisabled();
	});

	it("asks for confirmation before granting admin, and cancels without change", async () => {
		vi.spyOn(window, "confirm").mockReturnValue(false);
		renderPage();
		await screen.findByText("someone@example.com");

		const otherRow = rowFor("someone@example.com");
		const adminCheckbox = within(otherRow).getByRole("checkbox", {
			name: "管理者",
		});

		const user = userEvent.setup();
		await user.click(adminCheckbox);

		expect(window.confirm).toHaveBeenCalledWith(
			"someone@example.com に管理者権限を付与しますか?",
		);
		expect(adminCheckbox).not.toBeChecked();
	});

	it("grants admin after confirming", async () => {
		vi.spyOn(window, "confirm").mockReturnValue(true);
		renderPage();
		await screen.findByText("someone@example.com");

		const otherRow = rowFor("someone@example.com");
		const adminCheckbox = within(otherRow).getByRole("checkbox", {
			name: "管理者",
		});

		const user = userEvent.setup();
		await user.click(adminCheckbox);

		await waitFor(() => expect(adminCheckbox).toBeChecked());
	});

	it("disables (無効化) another user via the PATCH endpoint after confirming", async () => {
		vi.spyOn(window, "confirm").mockReturnValue(true);
		renderPage();
		await screen.findByText("someone@example.com");

		const otherRow = rowFor("someone@example.com");
		const disabledCheckbox = within(otherRow).getByRole("checkbox", {
			name: "無効",
		});

		const user = userEvent.setup();
		await user.click(disabledCheckbox);

		expect(window.confirm).toHaveBeenCalledWith(
			"someone@example.com を無効化しますか?",
		);
		await waitFor(() => expect(disabledCheckbox).toBeChecked());
	});
});
