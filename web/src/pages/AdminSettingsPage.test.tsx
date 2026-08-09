import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthSettings } from "../api/types";
import { AuthProvider } from "../auth/AuthContext";
import { AdminSettingsPage } from "./AdminSettingsPage";

const adminUser = {
	id: "admin-1",
	email: "admin@example.com",
	is_system_admin: true,
};
const settings: AuthSettings = {
	local_auth_enabled: true,
	self_signup_enabled: true,
	require_email_confirmation_for_signup: true,
	require_reauth_for_account_link: true,
};

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
					<AdminSettingsPage />
				</AuthProvider>
			</MemoryRouter>
		</QueryClientProvider>,
	);
}

describe("AdminSettingsPage", () => {
	beforeEach(() => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async (url: string, init?: RequestInit) => {
				if (url.endsWith("/api/auth/me")) {
					return jsonResponse(adminUser);
				}
				if (url.endsWith("/api/admin/auth-settings")) {
					if (init?.method === "PATCH") {
						const body = JSON.parse(init.body as string);
						return jsonResponse({ ...settings, ...body });
					}
					return jsonResponse(settings);
				}
				return new Response(null, { status: 404 });
			}),
		);
	});

	afterEach(() => {
		cleanup();
		vi.unstubAllGlobals();
	});

	it("renders every setting as a checked checkbox", async () => {
		renderPage();
		const checkboxes = (await screen.findAllByRole(
			"checkbox",
		)) as HTMLInputElement[];
		expect(checkboxes).toHaveLength(4);
		for (const cb of checkboxes) {
			expect(cb.checked).toBe(true);
		}
	});

	it("PATCHes the toggled setting and reflects the response", async () => {
		renderPage();
		const checkbox = (await screen.findByLabelText(
			/ローカル認証/,
		)) as HTMLInputElement;

		const user = userEvent.setup();
		await user.click(checkbox);

		await waitFor(() => expect(checkbox.checked).toBe(false));

		const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls as [
			string,
			RequestInit | undefined,
		][];
		const patchCall = calls.find(([, init]) => init?.method === "PATCH");
		expect(patchCall).toBeDefined();
		expect(JSON.parse(patchCall?.[1]?.body as string)).toEqual({
			local_auth_enabled: false,
		});
	});
});
