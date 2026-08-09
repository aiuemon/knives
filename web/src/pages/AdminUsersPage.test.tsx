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

	it("disables revoking the caller's own system_admin status", async () => {
		renderPage();
		await screen.findByText("admin@example.com");

		const rows = screen.getAllByRole("row");
		const selfRow = rows.find((r) =>
			within(r).queryByText("admin@example.com"),
		);
		expect(selfRow).toBeDefined();
		const revokeButton = within(selfRow as HTMLElement).getByRole("button", {
			name: "admin権限を剥奪",
		});
		expect(revokeButton).toBeDisabled();
	});

	it("suspends another user via the PATCH endpoint", async () => {
		renderPage();
		await screen.findByText("someone@example.com");

		const rows = screen.getAllByRole("row");
		const otherRow = rows.find((r) =>
			within(r).queryByText("someone@example.com"),
		) as HTMLElement;
		const suspendButton = within(otherRow).getByRole("button", {
			name: "凍結",
		});

		const user = userEvent.setup();
		await user.click(suspendButton);

		await waitFor(() =>
			expect(
				within(otherRow).getByRole("button", { name: "凍結解除" }),
			).toBeInTheDocument(),
		);
	});
});
