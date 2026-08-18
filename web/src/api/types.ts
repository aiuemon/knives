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
	created_at: string;
	// your_role/can_* describe what the calling user may do with this URL
	// (4.2節). your_role is "" when visibility comes purely from a
	// system_admin's unlimited-view override (4.1節) rather than an
	// actual url_permissions grant — in that case every can_* is false.
	your_role?: string;
	can_edit: boolean;
	can_delete: boolean;
	can_manage_permissions: boolean;
}

// ShortURLListItem is one row of GET /short-urls (4.1節の一覧表示).
// creator_email is present only when the caller is a system_admin.
export interface ShortURLListItem extends ShortURL {
	click_count: number;
	creator_email?: string;
}

// "short_code" | "long_url" | "title" | "created_at" | "click_count" | "creator_email"
export type ShortURLSortField =
	| "short_code"
	| "long_url"
	| "title"
	| "created_at"
	| "click_count"
	| "creator_email";

export type SortDirection = "asc" | "desc";

export interface ShortURLListResponse {
	items: ShortURLListItem[];
	total: number;
}

export interface ShortURLDailyStat {
	date: string;
	click_count: number;
}

export interface ShortURLHourlyStat {
	hour: string; // RFC3339
	click_count: number;
}

export interface ShortURLReferrerStat {
	referrer_host: string;
	click_count: number;
}

export interface ShortURLCountryStat {
	country_code: string; // ISO 3166-1 alpha-2。GeoIP未設定/未解決時は""
	click_count: number;
}

export interface ShortURLOSStat {
	os: string; // 分類不能時は""
	click_count: number;
}

// browserは分類不能時は""、上位10種以外をまとめた合算枠は"other"
export interface ShortURLBrowserStat {
	browser: string;
	click_count: number;
}

// ShortURLStats is GET /short-urls/{id}/stats (4節)。from/toはリクエストで
// 指定した(または既定の)日付範囲そのまま(YYYY-MM-DD)。granularityに応じて
// dailyまたはhourlyの一方だけが入る。
export interface ShortURLStats {
	from: string;
	to: string;
	granularity: "day" | "hour";
	daily?: ShortURLDailyStat[];
	hourly?: ShortURLHourlyStat[];
	by_referrer: ShortURLReferrerStat[];
	by_country: ShortURLCountryStat[];
	by_os: ShortURLOSStat[];
	by_browser: ShortURLBrowserStat[];
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

// WebAuthnCredential is one registered passkey (3.1節). id is the DB row
// id (used to revoke/rename it) — the raw credential_id/public_key are
// never exposed to the client. last_used_at is absent until the passkey
// has actually been used to log in at least once (registering it doesn't
// count).
export interface WebAuthnCredential {
	id: string;
	name: string;
	transports?: string[];
	created_at: string;
	last_used_at?: string;
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
