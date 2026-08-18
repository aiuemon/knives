package geoip_test

import (
	"net"
	"testing"

	"github.com/aiuemon/knives/internal/geoip"
)

func TestNoopResolver_AlwaysUnresolved(t *testing.T) {
	r := geoip.NoopResolver{}
	code, ok := r.Lookup(net.ParseIP("203.0.113.1"))
	if ok || code != "" {
		t.Fatalf("expected NoopResolver to always report unresolved, got (%q, %v)", code, ok)
	}
}

func TestOpenMaxMindResolver_MissingFileReturnsError(t *testing.T) {
	// GEOIP_DB_PATHが未設定/誤設定の場合はサーバ起動を落とさずNoop
	// resolverへfallbackする(呼び出し側の責務)ため、ここではOpen自体が
	// エラーを返すことだけを確認する。
	if _, err := geoip.OpenMaxMindResolver("/nonexistent/path/to.mmdb"); err == nil {
		t.Fatalf("expected an error opening a nonexistent .mmdb file")
	}
}
