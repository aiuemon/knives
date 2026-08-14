package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// yourlsTimestampLayout matches MySQL's default DATETIME text
// representation, which is what a plain `SELECT * FROM yourls_url`
// export (mysqldump --tab, phpMyAdmin CSV export, etc.) produces for
// yourls_url.timestamp.
const yourlsTimestampLayout = "2006-01-02 15:04:05"

// yourlsRow is one row of a YOURLS yourls_url export (10節: keyword, url,
// title, timestamp, clicks — YOURLS' ip column carries no useful
// per-click detail beyond the cumulative clicks count, so it's not read).
type yourlsRow struct {
	Keyword   string
	URL       string
	Title     string
	CreatedAt time.Time
	Clicks    int64
}

// readYourlsCSV reads a YOURLS yourls_url export: a header row containing
// (at minimum) keyword,url,title,timestamp,clicks in any column order,
// plus extra columns are ignored. It validates every row before returning
// any of them — a migration run should never partially apply because one
// row further down turned out to be malformed.
func readYourlsCSV(path string) ([]yourlsRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	idx, err := columnIndex(header, "keyword", "url", "title", "timestamp", "clicks")
	if err != nil {
		return nil, err
	}

	var rows []yourlsRow
	for line := 2; ; line++ {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}

		keyword := strings.TrimSpace(rec[idx["keyword"]])
		if keyword == "" {
			return nil, fmt.Errorf("line %d: empty keyword", line)
		}
		clicks, err := strconv.ParseInt(strings.TrimSpace(rec[idx["clicks"]]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("line %d (keyword=%q): invalid clicks: %w", line, keyword, err)
		}
		createdAt, err := time.Parse(yourlsTimestampLayout, strings.TrimSpace(rec[idx["timestamp"]]))
		if err != nil {
			return nil, fmt.Errorf("line %d (keyword=%q): invalid timestamp: %w", line, keyword, err)
		}

		rows = append(rows, yourlsRow{
			Keyword:   keyword,
			URL:       strings.TrimSpace(rec[idx["url"]]),
			Title:     strings.TrimSpace(rec[idx["title"]]),
			CreatedAt: createdAt,
			Clicks:    clicks,
		})
	}
	return rows, nil
}

// readOwnersCSV reads the keyword->owner email mapping CSV (10節). A
// header row with columns keyword,owner_email is required. path == ""
// (no --owners-csv given) is valid and yields an empty map — every URL
// then falls back to the migration system user as owner.
func readOwnersCSV(path string) (map[string]string, error) {
	if path == "" {
		return map[string]string{}, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	idx, err := columnIndex(header, "keyword", "owner_email")
	if err != nil {
		return nil, err
	}

	owners := map[string]string{}
	for line := 2; ; line++ {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		keyword := strings.TrimSpace(rec[idx["keyword"]])
		email := strings.TrimSpace(rec[idx["owner_email"]])
		if keyword == "" || email == "" {
			return nil, fmt.Errorf("line %d: keyword and owner_email must both be non-empty", line)
		}
		owners[keyword] = email
	}
	return owners, nil
}

// columnIndex maps each of required to its position in header (case/space
// insensitive), erroring out immediately if any is missing — a wrong
// column name should be caught before reading a single data row, not
// discovered as a confusing per-row failure.
func columnIndex(header []string, required ...string) (map[string]int, error) {
	idx := map[string]int{}
	for i, h := range header {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	for _, col := range required {
		if _, ok := idx[col]; !ok {
			return nil, fmt.Errorf("missing required column %q (found: %s)", col, strings.Join(header, ", "))
		}
	}
	return idx, nil
}
