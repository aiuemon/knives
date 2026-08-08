import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../auth/AuthContext";
import { LoginPage } from "./LoginPage";

function renderLoginPage() {
	const queryClient = new QueryClient({
		defaultOptions: { queries: { retry: false } },
	});
	return render(
		<QueryClientProvider client={queryClient}>
			<MemoryRouter>
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
});
