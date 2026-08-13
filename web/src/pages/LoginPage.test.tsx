import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../auth/AuthContext";
import { loginWithPasskey } from "../lib/webauthn";
import { LoginPage } from "./LoginPage";

vi.mock("../lib/webauthn", () => ({
	loginWithPasskey: vi.fn(),
}));

function renderLoginPage(initialEntries = ["/login"]) {
	const queryClient = new QueryClient({
		defaultOptions: { queries: { retry: false } },
	});
	return render(
		<QueryClientProvider client={queryClient}>
			<MemoryRouter initialEntries={initialEntries}>
				<AuthProvider>
					<LoginPage />
				</AuthProvider>
			</MemoryRouter>
		</QueryClientProvider>,
	);
}

describe("LoginPage", () => {
	beforeEach(() => {
		// AuthProvider fetches /api/auth/me on mount; simulate "not logged in".
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => new Response(null, { status: 401 })),
		);
	});

	afterEach(() => {
		cleanup();
		vi.unstubAllGlobals();
	});

	it("renders email and password fields", async () => {
		renderLoginPage();
		expect(
			await screen.findByRole("heading", { name: "ログイン" }),
		).toBeInTheDocument();
		expect(screen.getByLabelText("メールアドレス")).toBeInTheDocument();
		expect(screen.getByLabelText("パスワード")).toBeInTheDocument();
	});

	it("lets the user type into the email field", async () => {
		renderLoginPage();
		const user = userEvent.setup();
		const email = screen.getByLabelText("メールアドレス") as HTMLInputElement;
		await user.type(email, "person@example.com");
		expect(email.value).toBe("person@example.com");
	});

	it("renders a login link for each enabled SAML IdP", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async (url: string) => {
				if (url.endsWith("/api/auth/saml/idps")) {
					return new Response(
						JSON.stringify([{ id: "idp-1", name: "社内ADFS" }]),
						{ status: 200, headers: { "Content-Type": "application/json" } },
					);
				}
				return new Response(null, { status: 401 });
			}),
		);
		renderLoginPage();

		const link = await screen.findByRole("link", {
			name: "社内ADFS でログイン",
		});
		expect(link).toHaveAttribute("href", "/api/auth/saml/idp-1/login");
	});

	it("shows a pending-confirmation notice from the SAML redirect", async () => {
		renderLoginPage(["/login?notice=saml_pending_confirmation"]);
		expect(
			await screen.findByText(/確認メールを送信しました/),
		).toBeInTheDocument();
	});

	it("shows a generic error notice when SAML login fails", async () => {
		renderLoginPage(["/login?error=saml_failed"]);
		expect(
			await screen.findByText(/SSOログインに失敗しました/),
		).toBeInTheDocument();
	});

	it("renders a login link for each enabled OIDC IdP", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async (url: string) => {
				if (url.endsWith("/api/auth/oidc/idps")) {
					return new Response(
						JSON.stringify([{ id: "idp-2", name: "社内Entra ID" }]),
						{ status: 200, headers: { "Content-Type": "application/json" } },
					);
				}
				return new Response(null, { status: 401 });
			}),
		);
		renderLoginPage();

		const link = await screen.findByRole("link", {
			name: "社内Entra ID でログイン",
		});
		expect(link).toHaveAttribute("href", "/api/auth/oidc/idp-2/login");
	});

	it("shows a pending-confirmation notice from the OIDC redirect", async () => {
		renderLoginPage(["/login?notice=oidc_pending_confirmation"]);
		expect(
			await screen.findByText(/確認メールを送信しました/),
		).toBeInTheDocument();
	});

	it("shows a generic error notice when OIDC login fails", async () => {
		renderLoginPage(["/login?error=oidc_failed"]);
		expect(
			await screen.findByText(/SSOログインに失敗しました/),
		).toBeInTheDocument();
	});

	it("triggers a passkey login when the passkey button is clicked", async () => {
		vi.mocked(loginWithPasskey).mockResolvedValue(undefined);
		renderLoginPage();

		const user = userEvent.setup();
		await user.click(
			await screen.findByRole("button", { name: "パスキーでログイン" }),
		);

		await waitFor(() => expect(loginWithPasskey).toHaveBeenCalled());
	});

	it("shows an error message when the passkey login fails", async () => {
		vi.mocked(loginWithPasskey).mockRejectedValue(new Error("cancelled"));
		renderLoginPage();

		const user = userEvent.setup();
		await user.click(
			await screen.findByRole("button", { name: "パスキーでログイン" }),
		);

		expect(
			await screen.findByText("パスキーでのログインに失敗しました"),
		).toBeInTheDocument();
	});
});
