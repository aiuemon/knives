import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { PendingLink } from "../api/types";
import { AuthProvider } from "../auth/AuthContext";
import { Header } from "./Header";

const me = {
	id: "user-1",
	email: "user@example.com",
	is_system_admin: false,
};

function jsonResponse(body: unknown, status = 200) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function renderHeader(pendingLinks: PendingLink[]) {
	const queryClient = new QueryClient({
		defaultOptions: { queries: { retry: false } },
	});
	vi.stubGlobal(
		"fetch",
		vi.fn(async (url: string) => {
			if (url.endsWith("/api/auth/me")) {
				return jsonResponse(me);
			}
			if (url.endsWith("/api/auth/pending-links")) {
				return jsonResponse(pendingLinks);
			}
			return new Response(null, { status: 404 });
		}),
	);
	return render(
		<QueryClientProvider client={queryClient}>
			<MemoryRouter>
				<AuthProvider>
					<Header />
				</AuthProvider>
			</MemoryRouter>
		</QueryClientProvider>,
	);
}

const pendingLink: PendingLink = {
	id: "pending-1",
	provider_type: "saml",
	expires_at: "2026-01-01T00:00:00Z",
};

describe("Header", () => {
	afterEach(() => {
		cleanup();
		vi.unstubAllGlobals();
	});

	it("hides the pending-link entry entirely when there are no pending requests", async () => {
		renderHeader([]);
		await screen.findByText(me.email);
		expect(
			screen.queryByText("保留中の統合リクエスト"),
		).not.toBeInTheDocument();
	});

	it("shows the pending-link entry with a count badge when there are pending requests", async () => {
		renderHeader([pendingLink, { ...pendingLink, id: "pending-2" }]);
		const link = await screen.findByRole("link", {
			name: /保留中の統合リクエスト/,
		});
		expect(link).toHaveAttribute("href", "/pending-links");
		expect(link).toHaveTextContent("2");
	});
});
