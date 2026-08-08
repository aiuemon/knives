const API_BASE = "/api";

export class ApiError extends Error {
	status: number;
	constructor(status: number, message: string) {
		super(message);
		this.status = status;
	}
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
	const res = await fetch(`${API_BASE}${path}`, {
		...init,
		credentials: "include",
		headers: {
			...(init?.body ? { "Content-Type": "application/json" } : {}),
			...init?.headers,
		},
	});
	if (!res.ok) {
		const text = await res.text();
		throw new ApiError(res.status, text.trim() || res.statusText);
	}
	if (res.status === 204) {
		return undefined as T;
	}
	return (await res.json()) as T;
}

export const api = {
	get: <T>(path: string) => request<T>(path),
	post: <T>(path: string, body?: unknown) =>
		request<T>(path, {
			method: "POST",
			body: body !== undefined ? JSON.stringify(body) : undefined,
		}),
};
