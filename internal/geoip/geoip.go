// Package geoip resolves a client IP address to its country (4節: 国別
// 統計)。呼び出し側(cmd/redirect)は、IPを一方向ハッシュ化してclick_events
// に書き込む前に必ずここを通す必要がある — ip_hashは不可逆なため、国の
// 解決はリダイレクト時点でしか行えない(保存済みのクリック履歴からは
// 後から絶対に復元できない)。
package geoip

import "net"

// Resolver looks up an IP address's country.
type Resolver interface {
	// Lookup returns the ISO 3166-1 alpha-2 country code for ip, or ""
	// with ok=false if it couldn't be resolved (unknown/private IP,
	// lookup error, or no database configured).
	Lookup(ip net.IP) (countryCode string, ok bool)
}

// NoopResolver always reports unresolved. It's the default when no GeoIP
// database is configured (GEOIP_DB_PATH unset) — country_code simply
// stays NULL, matching this system's behavior before GeoIP support
// existed, rather than the server failing to start.
type NoopResolver struct{}

func (NoopResolver) Lookup(net.IP) (string, bool) { return "", false }

var _ Resolver = NoopResolver{}
