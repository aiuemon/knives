package useragent_test

import (
	"testing"

	"github.com/aiuemon/knives/internal/useragent"
)

func TestCategorize(t *testing.T) {
	tests := []struct {
		name        string
		ua          string
		wantOS      string
		wantBrowser string
	}{
		{
			name:        "Windows + Chrome",
			ua:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			wantOS:      "Windows",
			wantBrowser: "Chrome",
		},
		{
			name:        "macOS + Safari",
			ua:          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
			wantOS:      "macOS",
			wantBrowser: "Safari",
		},
		{
			name:        "iPhone + Safari",
			ua:          "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			wantOS:      "iOS",
			wantBrowser: "Safari",
		},
		{
			name:        "iPad explicitly identifying itself is classified as iPadOS",
			ua:          "Mozilla/5.0 (iPad; CPU OS 13_1_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 Mobile/15E148 Safari/604.1",
			wantOS:      "iPadOS",
			wantBrowser: "Safari",
		},
		{
			name:        "Android + Chrome",
			ua:          "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
			wantOS:      "Android",
			wantBrowser: "Chrome",
		},
		{
			name:        "Ubuntu + Firefox",
			ua:          "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
			wantOS:      "Ubuntu",
			wantBrowser: "Firefox",
		},
		{
			name:        "Debian + Firefox",
			ua:          "Mozilla/5.0 (X11; Debian; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
			wantOS:      "Debian",
			wantBrowser: "Firefox",
		},
		{
			name:        "generic Linux without a distro token falls back to Linux",
			ua:          "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			wantOS:      "Linux",
			wantBrowser: "Chrome",
		},
		{
			name:        "FreeBSD + Firefox",
			ua:          "Mozilla/5.0 (X11; FreeBSD amd64; rv:120.0) Gecko/20100101 Firefox/120.0",
			wantOS:      "FreeBSD",
			wantBrowser: "Firefox",
		},
		{
			name:        "empty User-Agent is unknown",
			ua:          "",
			wantOS:      "",
			wantBrowser: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOS, gotBrowser := useragent.Categorize(tt.ua)
			if gotOS != tt.wantOS {
				t.Errorf("os = %q, want %q", gotOS, tt.wantOS)
			}
			if gotBrowser != tt.wantBrowser {
				t.Errorf("browser = %q, want %q", gotBrowser, tt.wantBrowser)
			}
		})
	}
}

func TestCategorize_BrowserIgnoresVersionDifferences(t *testing.T) {
	older := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36"
	newer := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	_, olderBrowser := useragent.Categorize(older)
	_, newerBrowser := useragent.Categorize(newer)

	if olderBrowser != newerBrowser {
		t.Fatalf("expected different Chrome versions to be treated as the same browser family, got %q vs %q", olderBrowser, newerBrowser)
	}
	if olderBrowser != "Chrome" {
		t.Fatalf("expected browser family %q, got %q", "Chrome", olderBrowser)
	}
}
