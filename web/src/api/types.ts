export interface User {
	id: string;
	email: string;
}

export interface ShortURL {
	id: string;
	short_code: string;
	long_url: string;
	title?: string;
	description?: string;
	status: string;
	expires_at?: string;
}

export interface SignupResponse {
	// "logged_in" | "verification_pending"
	status: string;
}

export interface PendingLink {
	id: string;
	provider_type: string;
	expires_at: string;
}
