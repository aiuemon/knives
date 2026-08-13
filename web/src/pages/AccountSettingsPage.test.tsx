import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { WebAuthnCredential } from "../api/types";
import { AuthProvider } from "../auth/AuthContext";
import { registerPasskey } from "../lib/webauthn";
import { AccountSettingsPage } from "./AccountSettingsPage";

vi.mock("../lib/webauthn", () => ({
	registerPasskey: vi.fn(),
}));

const me = {
	id: "user-1",
	email: "user@example.com",
	is_system_admin: false,
};

const credential: WebAuthnCredential = {
	id: "cred-1",
	transports: ["internal"],
};

function jsonResponse(body: unknown, status = 200) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function renderPage(
	credentials: WebAuthnCredential[],
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
			if (url.endsWith("/api/auth/webauthn/credentials")) {
				return jsonResponse(credentials);
			}
			return new Response(null, { status: 404 });
		}),
	);
	return render(
		<QueryClientProvider client={queryClient}>
			<MemoryRouter>
				<AuthProvider>
					<AccountSettingsPage />
				</AuthProvider>
			</MemoryRouter>
		</QueryClientProvider>,
	);
}

describe("AccountSettingsPage", () => {
	afterEach(() => {
		cleanup();
		vi.unstubAllGlobals();
		vi.mocked(registerPasskey).mockReset();
	});

	it("lists registered passkeys with their transport labels", async () => {
		renderPage([credential]);
		expect(
			await screen.findByText("端末内蔵(指紋・顔認証など)"),
		).toBeInTheDocument();
	});

	it("shows an empty state when there are no passkeys", async () => {
		renderPage([]);
		expect(
			await screen.findByText("登録済みのパスキーはありません。"),
		).toBeInTheDocument();
	});

	it("registers a new passkey and refreshes the list", async () => {
		vi.mocked(registerPasskey).mockResolvedValue(undefined);
		let listCallCount = 0;
		renderPage([], (url, init) => {
			if (
				url.endsWith("/api/auth/webauthn/credentials") &&
				(!init || init.method === undefined)
			) {
				listCallCount += 1;
				return jsonResponse(listCallCount === 1 ? [] : [credential]);
			}
			return undefined;
		});
		await screen.findByText("登録済みのパスキーはありません。");

		const user = userEvent.setup();
		await user.click(screen.getByRole("button", { name: "パスキーを登録" }));

		await waitFor(() => expect(registerPasskey).toHaveBeenCalled());
		expect(
			await screen.findByText("端末内蔵(指紋・顔認証など)"),
		).toBeInTheDocument();
	});

	it("revokes a passkey after confirmation", async () => {
		vi.spyOn(window, "confirm").mockReturnValue(true);
		renderPage([credential], (url, init) => {
			if (
				url.endsWith("/api/auth/webauthn/credentials/cred-1") &&
				init?.method === "DELETE"
			) {
				return new Response(null, { status: 204 });
			}
			return undefined;
		});
		await screen.findByText("端末内蔵(指紋・顔認証など)");

		const user = userEvent.setup();
		await user.click(screen.getByRole("button", { name: "削除" }));

		await waitFor(() =>
			expect(
				screen.queryByText("端末内蔵(指紋・顔認証など)"),
			).not.toBeInTheDocument(),
		);
	});
});
