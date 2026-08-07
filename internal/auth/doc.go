// Package auth is the authentication core shared by cmd/api and cmd/worker.
// It centralizes identity resolution and account-linking logic across
// local/passkey, SAML, and OIDC login flows (see docs/architecture.md, 3.4節).
package auth
