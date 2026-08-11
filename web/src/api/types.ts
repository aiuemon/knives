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
	// your_role/can_* describe what the calling user may do with this URL
	// (4.2節). your_role is "" when visibility comes purely from a
	// system_admin's unlimited-view override (4.1節) rather than an
	// actual url_permissions grant — in that case every can_* is false.
	your_role?: string;
	can_edit: boolean;
	can_delete: boolean;
	can_manage_permissions: boolean;
}

export interface URLPermissionGrant {
	user_id: string;
	email: string;
	// "owner" | "editor" | "viewer"
	role: string;
	granted_at: string;
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

// PublicOIDCIdP is the unauthenticated login-page view of an OIDC IdP —
// just enough to render a "Login with X" link.
export interface PublicOIDCIdP {
	id: string;
	name: string;
}

// OIDCConfig never carries client_secret — the API never sends it back
// once stored. See AdminOIDCConfigsPage for how edits without a new
// secret are handled.
export interface OIDCConfig {
	id: string;
	name: string;
	issuer: string;
	client_id: string;
	scopes: string[];
	require_email_verified_claim: boolean;
	enabled: boolean;
}
