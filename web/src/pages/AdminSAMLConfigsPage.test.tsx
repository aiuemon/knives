import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SAMLConfig } from "../api/types";
import { AuthProvider } from "../auth/AuthContext";
import { AdminSAMLConfigsPage } from "./AdminSAMLConfigsPage";

const me = {
	id: "admin-1",
	email: "admin@example.com",
	is_system_admin: true,
};

const existingConfig: SAMLConfig = {
	id: "cfg-1",
	name: "社内ADFS",
	idp_entity_id: "https://adfs.example.com/adfs/services/trust",
	idp_sso_url: "https://adfs.example.com/adfs/ls/",
	idp_certificate:
		"-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
	email_attribute: "email",
	trusted: true,
	enabled: true,
};

function jsonResponse(body: unknown, status = 200) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function renderPage(configs: SAMLConfig[]) {
	const queryClient = new QueryClient({
		defaultOptions: { queries: { retry: false } },
	});
	vi.stubGlobal(
		"fetch",
		vi.fn(async (url: string, init?: RequestInit) => {
			if (url.endsWith("/api/auth/me")) {
				return jsonResponse(me);
			}
			if (url.endsWith("/api/admin/saml-configs")) {
				if (init?.method === "POST") {
					const body = JSON.parse(init.body as string);
					return jsonResponse({ id: "cfg-new", ...body }, 201);
				}
				return jsonResponse(configs);
			}
			const match = url.match(/\/api\/admin\/saml-configs\/(.+)$/);
			if (match) {
				const id = match[1];
				if (init?.method === "PATCH") {
					const body = JSON.parse(init.body as string);
					return jsonResponse({ id, ...body });
				}
				if (init?.method === "DELETE") {
					return new Response(null, { status: 204 });
				}
			}
			return new Response(null, { status: 404 });
		}),
	);
	return render(
		<QueryClientProvider client={queryClient}>
			<MemoryRouter>
				<AuthProvider>
					<AdminSAMLConfigsPage />
				</AuthProvider>
			</MemoryRouter>
		</QueryClientProvider>,
	);
}

describe("AdminSAMLConfigsPage", () => {
	afterEach(() => {
		cleanup();
		vi.unstubAllGlobals();
	});

	it("lists existing IdP configs", async () => {
		renderPage([existingConfig]);
		expect(await screen.findByText("社内ADFS")).toBeInTheDocument();
		expect(
			screen.getByText("https://adfs.example.com/adfs/services/trust"),
		).toBeInTheDocument();
	});

	it("submits the add form as a POST", async () => {
		renderPage([]);
		await screen.findByRole("heading", { name: "IdPを追加" });

		const user = userEvent.setup();
		await user.type(screen.getByLabelText("表示名"), "テストIdP");
		await user.type(
			screen.getByLabelText("IdP Entity ID"),
			"https://idp.example.com/entity",
		);
		await user.type(
			screen.getByLabelText("IdP SSO URL"),
			"https://idp.example.com/sso",
		);
		await user.type(
			screen.getByLabelText("IdP証明書(PEM形式)"),
			"-----BEGIN CERTIFICATE-----",
		);
		await user.type(screen.getByLabelText("メールアドレスの属性名"), "email");
		await user.click(screen.getByRole("button", { name: "追加" }));

		await waitFor(() =>
			expect(screen.getByText("テストIdP")).toBeInTheDocument(),
		);

		const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls as [
			string,
			RequestInit | undefined,
		][];
		const postCall = calls.find(([, init]) => init?.method === "POST");
		expect(postCall).toBeDefined();
		expect(JSON.parse(postCall?.[1]?.body as string)).toMatchObject({
			name: "テストIdP",
			idp_entity_id: "https://idp.example.com/entity",
		});
	});

	it("deletes a config after confirmation", async () => {
		vi.spyOn(window, "confirm").mockReturnValue(true);
		renderPage([existingConfig]);
		await screen.findByText("社内ADFS");

		const user = userEvent.setup();
		await user.click(screen.getByRole("button", { name: "削除" }));

		await waitFor(() =>
			expect(screen.queryByText("社内ADFS")).not.toBeInTheDocument(),
		);
	});

	it("shows a conflict error when deletion is refused", async () => {
		vi.spyOn(window, "confirm").mockReturnValue(true);
		const queryClient = new QueryClient({
			defaultOptions: { queries: { retry: false } },
		});
		vi.stubGlobal(
			"fetch",
			vi.fn(async (url: string, init?: RequestInit) => {
				if (url.endsWith("/api/auth/me")) {
					return jsonResponse(me);
				}
				if (init?.method === "DELETE") {
					return new Response("saml config still has linked users", {
						status: 409,
					});
				}
				if (url.endsWith("/api/admin/saml-configs")) {
					return jsonResponse([existingConfig]);
				}
				return new Response(null, { status: 404 });
			}),
		);
		render(
			<QueryClientProvider client={queryClient}>
				<MemoryRouter>
					<AuthProvider>
						<AdminSAMLConfigsPage />
					</AuthProvider>
				</MemoryRouter>
			</QueryClientProvider>,
		);

		await screen.findByText("社内ADFS");
		const user = userEvent.setup();
		await user.click(screen.getByRole("button", { name: "削除" }));

		expect(await screen.findByText(/linked users/)).toBeInTheDocument();
		expect(screen.getByText("社内ADFS")).toBeInTheDocument();
	});
});
