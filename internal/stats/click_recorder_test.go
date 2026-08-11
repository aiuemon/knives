package stats

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fakeStore struct {
	inserted    map[string]ClickEvent // by StreamID
	dailyCounts map[string]int        // by shortURLID.String()+"|"+date
	upsertCalls int
	insertErr   error
	upsertErr   error
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		inserted:    map[string]ClickEvent{},
		dailyCounts: map[string]int{},
	}
}

func (s *fakeStore) InsertClickEvent(_ context.Context, ev ClickEvent) (bool, error) {
	if s.insertErr != nil {
		return false, s.insertErr
	}
	if _, exists := s.inserted[ev.StreamID]; exists {
		return false, nil
	}
	s.inserted[ev.StreamID] = ev
	return true, nil
}

func (s *fakeStore) UpsertDailyCount(_ context.Context, shortURLID uuid.UUID, date time.Time, delta int) error {
	if s.upsertErr != nil {
		return s.upsertErr
	}
	s.upsertCalls++
	key := shortURLID.String() + "|" + date.Format("2006-01-02")
	s.dailyCounts[key] += delta
	return nil
}

func TestRecorder_RecordBatch_InsertsAndAggregatesPerDay(t *testing.T) {
	store := newFakeStore()
	r := &Recorder{Store: store}

	urlA := uuid.New()
	urlB := uuid.New()
	day1 := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)

	events := []ClickEvent{
		{StreamID: "1-0", ShortURLID: urlA, ClickedAt: day1.Add(1 * time.Hour)},
		{StreamID: "2-0", ShortURLID: urlA, ClickedAt: day1.Add(2 * time.Hour)},
		{StreamID: "3-0", ShortURLID: urlA, ClickedAt: day2.Add(1 * time.Hour)},
		{StreamID: "4-0", ShortURLID: urlB, ClickedAt: day1.Add(3 * time.Hour)},
	}

	if err := r.RecordBatch(context.Background(), events); err != nil {
		t.Fatalf("RecordBatch: %v", err)
	}

	if len(store.inserted) != 4 {
		t.Fatalf("expected 4 click_events rows inserted, got %d", len(store.inserted))
	}

	want := map[string]int{
		urlA.String() + "|2026-08-10": 2,
		urlA.String() + "|2026-08-11": 1,
		urlB.String() + "|2026-08-10": 1,
	}
	if len(store.dailyCounts) != len(want) {
		t.Fatalf("expected %d daily rollup rows, got %+v", len(want), store.dailyCounts)
	}
	for k, v := range want {
		if store.dailyCounts[k] != v {
			t.Fatalf("expected %s to have count %d, got %d (%+v)", k, v, store.dailyCounts[k], store.dailyCounts)
		}
	}
}

func TestRecorder_RecordBatch_SkipsAlreadyInsertedEventsWithoutDoubleCounting(t *testing.T) {
	store := newFakeStore()
	r := &Recorder{Store: store}

	urlA := uuid.New()
	day := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)

	// 1回目の配送で正常に記録される。
	first := []ClickEvent{{StreamID: "dup-1", ShortURLID: urlA, ClickedAt: day}}
	if err := r.RecordBatch(context.Background(), first); err != nil {
		t.Fatalf("RecordBatch (first): %v", err)
	}

	// at-least-once配送により同じStream Entryが再度届く(6節-5)。
	redelivered := []ClickEvent{
		{StreamID: "dup-1", ShortURLID: urlA, ClickedAt: day},
		{StreamID: "new-1", ShortURLID: urlA, ClickedAt: day},
	}
	if err := r.RecordBatch(context.Background(), redelivered); err != nil {
		t.Fatalf("RecordBatch (redelivered): %v", err)
	}

	key := urlA.String() + "|2026-08-10"
	if store.dailyCounts[key] != 2 {
		t.Fatalf("expected the redelivered duplicate to not be double-counted (want 2, got %d)", store.dailyCounts[key])
	}
}

func TestRecorder_RecordBatch_PropagatesInsertError(t *testing.T) {
	store := newFakeStore()
	store.insertErr = context.DeadlineExceeded
	r := &Recorder{Store: store}

	err := r.RecordBatch(context.Background(), []ClickEvent{{StreamID: "1-0", ShortURLID: uuid.New(), ClickedAt: time.Now()}})
	if err == nil {
		t.Fatalf("expected RecordBatch to propagate the store's insert error")
	}
	if store.upsertCalls != 0 {
		t.Fatalf("expected no daily upsert when insert fails, got %d calls", store.upsertCalls)
	}
}

func TestRecorder_RecordBatch_EmptyBatchIsANoOp(t *testing.T) {
	store := newFakeStore()
	r := &Recorder{Store: store}

	if err := r.RecordBatch(context.Background(), nil); err != nil {
		t.Fatalf("RecordBatch: %v", err)
	}
	if len(store.inserted) != 0 || store.upsertCalls != 0 {
		t.Fatalf("expected no side effects for an empty batch")
	}
}
