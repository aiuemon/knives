import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { OIDCConfig } from "../api/types";
import { AuthProvider } from "../auth/AuthContext";
import { AdminOIDCConfigsPage } from "./AdminOIDCConfigsPage";

const me = {
	id: "admin-1",
	email: "admin@example.com",
	is_system_admin: true,
};

const existingConfig: OIDCConfig = {
	id: "cfg-1",
	name: "社内Entra ID",
	issuer: "https://login.microsoftonline.com/tenant-id/v2.0",
	client_id: "client-abc",
	scopes: ["openid", "email", "profile"],
	require_email_verified_claim: true,
	enabled: true,
};

function jsonResponse(body: unknown, status = 200) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function renderPage(configs: OIDCConfig[]) {
	const queryClient = new QueryClient({
		defaultOptions: { queries: { retry: false } },
	});
	vi.stubGlobal(
		"fetch",
		vi.fn(async (url: string, init?: RequestInit) => {
			if (url.endsWith("/api/auth/me")) {
				return jsonResponse(me);
			}
			if (url.endsWith("/api/admin/oidc-configs")) {
				if (init?.method === "POST") {
					const body = JSON.parse(init.body as string);
					return jsonResponse({ id: "cfg-new", ...body }, 201);
				}
				return jsonResponse(configs);
			}
			const match = url.match(/\/api\/admin\/oidc-configs\/(.+)$/);
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
					<AdminOIDCConfigsPage />
				</AuthProvider>
			</MemoryRouter>
		</QueryClientProvider>,
	);
}

describe("AdminOIDCConfigsPage", () => {
	afterEach(() => {
		cleanup();
		vi.unstubAllGlobals();
	});

	it("lists existing IdP configs", async () => {
		renderPage([existingConfig]);
		expect(await screen.findByText("社内Entra ID")).toBeInTheDocument();
		expect(
			screen.getByText("https://login.microsoftonline.com/tenant-id/v2.0"),
		).toBeInTheDocument();
	});

	it("submits the add form as a POST including the client secret", async () => {
		renderPage([]);
		await screen.findByRole("heading", { name: "IdPを追加" });

		const user = userEvent.setup();
		await user.type(screen.getByLabelText("表示名"), "テストIdP");
		await user.type(
			screen.getByLabelText("Issuer URL"),
			"https://idp.example.com",
		);
		await user.type(screen.getByLabelText("Client ID"), "test-client");
		await user.type(screen.getByLabelText("Client Secret"), "test-secret");
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
			client_id: "test-client",
			client_secret: "test-secret",
			scopes: ["openid", "email", "profile"],
		});
	});

	it("edits without re-entering the secret sends an empty client_secret", async () => {
		renderPage([existingConfig]);
		await screen.findByText("社内Entra ID");

		const user = userEvent.setup();
		await user.click(screen.getByRole("button", { name: "編集" }));

		const nameInput = (await screen.findByLabelText(
			"表示名",
		)) as HTMLInputElement;
		expect(nameInput.value).toBe("社内Entra ID");
		const secretInput = screen.getByLabelText(
			"Client Secret(変更する場合のみ入力)",
		) as HTMLInputElement;
		expect(secretInput.value).toBe("");

		await user.click(screen.getByRole("button", { name: "更新" }));

		await waitFor(() => {
			const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls as [
				string,
				RequestInit | undefined,
			][];
			const patchCall = calls.find(([, init]) => init?.method === "PATCH");
			expect(patchCall).toBeDefined();
			expect(JSON.parse(patchCall?.[1]?.body as string)).toMatchObject({
				client_secret: "",
			});
		});
	});

	it("deletes a config after confirmation", async () => {
		vi.spyOn(window, "confirm").mockReturnValue(true);
		renderPage([existingConfig]);
		await screen.findByText("社内Entra ID");

		const user = userEvent.setup();
		await user.click(screen.getByRole("button", { name: "削除" }));

		await waitFor(() =>
			expect(screen.queryByText("社内Entra ID")).not.toBeInTheDocument(),
		);
	});
});
