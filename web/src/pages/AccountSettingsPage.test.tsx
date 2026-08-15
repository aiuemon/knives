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
	name: "会社支給MacBook",
	transports: ["internal"],
	created_at: "2026-01-01T00:00:00Z",
};

const usedCredential: WebAuthnCredential = {
	...credential,
	id: "cred-2",
	last_used_at: "2026-01-02T00:00:00Z",
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
			if (
				url.endsWith("/api/auth/webauthn/credentials") &&
				(!init || init.method === undefined)
			) {
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

	it("lists registered passkeys with their name and transport label", async () => {
		renderPage([credential]);
		expect(await screen.findByText("会社支給MacBook")).toBeInTheDocument();
		expect(screen.getByText("端末内蔵(指紋・顔認証など)")).toBeInTheDocument();
	});

	it("shows registration date and 未使用 when the passkey has never been used", async () => {
		renderPage([credential]);
		await screen.findByText("会社支給MacBook");
		expect(screen.getByText("未使用")).toBeInTheDocument();
	});

	it("shows the last-used date when the passkey has been used", async () => {
		renderPage([usedCredential]);
		await screen.findByText("会社支給MacBook");
		expect(screen.queryByText("未使用")).not.toBeInTheDocument();
	});

	it("shows an empty state when there are no passkeys", async () => {
		renderPage([]);
		expect(
			await screen.findByText("登録済みのパスキーはありません。"),
		).toBeInTheDocument();
	});

	it("registers a new passkey with the entered name", async () => {
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
		await user.type(screen.getByLabelText("名称(任意)"), "会社支給MacBook");
		await user.click(screen.getByRole("button", { name: "パスキーを登録" }));

		await waitFor(() =>
			expect(registerPasskey).toHaveBeenCalledWith("会社支給MacBook"),
		);
		expect(await screen.findByText("会社支給MacBook")).toBeInTheDocument();
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
		await screen.findByText("会社支給MacBook");

		const user = userEvent.setup();
		await user.click(screen.getByRole("button", { name: "削除" }));

		await waitFor(() =>
			expect(screen.queryByText("会社支給MacBook")).not.toBeInTheDocument(),
		);
	});

	it("renames a passkey inline", async () => {
		renderPage([credential], (url, init) => {
			if (
				url.endsWith("/api/auth/webauthn/credentials/cred-1") &&
				init?.method === "PATCH"
			) {
				const body = JSON.parse(init.body as string);
				return jsonResponse({ ...credential, name: body.name });
			}
			return undefined;
		});
		await screen.findByText("会社支給MacBook");

		const user = userEvent.setup();
		await user.click(screen.getByRole("button", { name: "編集" }));

		const input = screen.getByLabelText("名称") as HTMLInputElement;
		await user.clear(input);
		await user.type(input, "私物MacBook");
		await user.click(screen.getByRole("button", { name: "保存" }));

		await waitFor(() =>
			expect(screen.getByText("私物MacBook")).toBeInTheDocument(),
		);
	});

	it("cancels an in-progress rename without saving", async () => {
		renderPage([credential]);
		await screen.findByText("会社支給MacBook");

		const user = userEvent.setup();
		await user.click(screen.getByRole("button", { name: "編集" }));
		const input = screen.getByLabelText("名称") as HTMLInputElement;
		await user.clear(input);
		await user.type(input, "変更中の名前");
		await user.click(screen.getByRole("button", { name: "キャンセル" }));

		expect(screen.getByText("会社支給MacBook")).toBeInTheDocument();
		expect(screen.queryByText("変更中の名前")).not.toBeInTheDocument();
	});
});
