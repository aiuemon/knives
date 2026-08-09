export interface User {
	id: string;
	email: string;
	is_system_admin: boolean;
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

export interface AuthSettings {
	local_auth_enabled: boolean;
	self_signup_enabled: boolean;
	require_email_confirmation_for_signup: boolean;
	require_reauth_for_account_link: boolean;
}

export interface AdminUser {
	id: string;
	email: string;
	email_verified: boolean;
	is_system_admin: boolean;
	// "active" | "suspended"
	status: string;
	created_at: string;
}
