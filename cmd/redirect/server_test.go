package main

import (
	"net/http"
	"testing"
)

func TestClientIP_StripsPort(t *testing.T) {
	r := &http.Request{RemoteAddr: "203.0.113.5:54321"}
	if got := clientIP(r); got != "203.0.113.5" {
		t.Fatalf("expected 203.0.113.5, got %q", got)
	}
}

func TestClientIP_FallsBackToRawWhenNoPort(t *testing.T) {
	r := &http.Request{RemoteAddr: "not-a-host-port"}
	if got := clientIP(r); got != "not-a-host-port" {
		t.Fatalf("expected the raw RemoteAddr as a fallback, got %q", got)
	}
}

func TestRefererHost_KeepsHostOnly(t *testing.T) {
	got := refererHost("https://social.example.com/some/path?utm_source=x")
	if got != "social.example.com" {
		t.Fatalf("expected only the host to be kept (privacy: 6節/2.2節 referrer_host), got %q", got)
	}
}

func TestRefererHost_EmptyForNoReferer(t *testing.T) {
	if got := refererHost(""); got != "" {
		t.Fatalf("expected empty string for no referer, got %q", got)
	}
}

func TestHashIP_IsDeterministicAndSaltSensitive(t *testing.T) {
	a := hashIP("198.51.100.1", "salt-a")
	b := hashIP("198.51.100.1", "salt-a")
	if a != b {
		t.Fatalf("hashIP must be deterministic for the same ip+salt")
	}
	if a == hashIP("198.51.100.1", "salt-b") {
		t.Fatalf("hashIP must depend on the salt (ip_hash設計: ソルト付きハッシュ)")
	}
	if a == "198.51.100.1" {
		t.Fatalf("hashIP must not leak the raw IP")
	}
}
