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

// PublicSAMLIdP is the unauthenticated login-page view of a SAML IdP —
// just enough to render a "Login with X" link. See SAMLConfig for the
// full admin-only view.
export interface PublicSAMLIdP {
	id: string;
	name: string;
}

export interface SAMLConfig {
	id: string;
	name: string;
	idp_entity_id: string;
	idp_sso_url: string;
	idp_certificate: string;
	email_attribute: string;
	trusted: boolean;
	enabled: boolean;
}
