package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTempCSV(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp csv: %v", err)
	}
	return path
}

func TestReadYourlsCSV_ParsesRowsRegardlessOfColumnOrder(t *testing.T) {
	path := writeTempCSV(t, "yourls.csv", "clicks,keyword,url,title,timestamp\n"+
		"42,abc123,https://example.com/a,Example A,2024-01-15 10:30:00\n"+
		"0,def456,https://example.com/b,Example B,2024-02-01 00:00:00\n")

	rows, err := readYourlsCSV(path)
	if err != nil {
		t.Fatalf("readYourlsCSV: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}
	if rows[0].Keyword != "abc123" || rows[0].URL != "https://example.com/a" || rows[0].Title != "Example A" || rows[0].Clicks != 42 {
		t.Fatalf("unexpected first row: %+v", rows[0])
	}
	wantTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	if !rows[0].CreatedAt.Equal(wantTime) {
		t.Fatalf("expected CreatedAt=%v, got %v", wantTime, rows[0].CreatedAt)
	}
}

func TestReadYourlsCSV_MissingColumnFailsBeforeAnyRowIsRead(t *testing.T) {
	path := writeTempCSV(t, "yourls.csv", "keyword,url,title,clicks\n"+
		"abc123,https://example.com/a,Example A,42\n")

	if _, err := readYourlsCSV(path); err == nil {
		t.Fatalf("expected an error for a missing timestamp column")
	}
}

func TestReadYourlsCSV_RejectsMalformedRowEntirely(t *testing.T) {
	path := writeTempCSV(t, "yourls.csv", "keyword,url,title,timestamp,clicks\n"+
		"abc123,https://example.com/a,Example A,2024-01-15 10:30:00,42\n"+
		"bad-row,https://example.com/b,Example B,not-a-date,0\n")

	if _, err := readYourlsCSV(path); err == nil {
		t.Fatalf("expected an error for a malformed timestamp, even though row 1 was valid")
	}
}

func TestReadYourlsCSV_RejectsEmptyKeyword(t *testing.T) {
	path := writeTempCSV(t, "yourls.csv", "keyword,url,title,timestamp,clicks\n"+
		" ,https://example.com/a,Example A,2024-01-15 10:30:00,0\n")

	if _, err := readYourlsCSV(path); err == nil {
		t.Fatalf("expected an error for an empty keyword")
	}
}

func TestReadOwnersCSV_EmptyPathYieldsEmptyMap(t *testing.T) {
	owners, err := readOwnersCSV("")
	if err != nil {
		t.Fatalf("readOwnersCSV(\"\"): %v", err)
	}
	if len(owners) != 0 {
		t.Fatalf("expected an empty map, got %+v", owners)
	}
}

func TestReadOwnersCSV_ParsesKeywordToEmailMapping(t *testing.T) {
	path := writeTempCSV(t, "owners.csv", "keyword,owner_email\n"+
		"abc123,owner1@example.com\n"+
		"def456,owner2@example.com\n")

	owners, err := readOwnersCSV(path)
	if err != nil {
		t.Fatalf("readOwnersCSV: %v", err)
	}
	if owners["abc123"] != "owner1@example.com" || owners["def456"] != "owner2@example.com" {
		t.Fatalf("unexpected mapping: %+v", owners)
	}
}

func TestReadOwnersCSV_RejectsEmptyEmail(t *testing.T) {
	path := writeTempCSV(t, "owners.csv", "keyword,owner_email\n"+
		"abc123,\n")

	if _, err := readOwnersCSV(path); err == nil {
		t.Fatalf("expected an error for an empty owner_email")
	}
}
