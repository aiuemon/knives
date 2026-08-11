DROP INDEX IF EXISTS idx_click_events_clicked_at_stream_id;
ALTER TABLE click_events DROP COLUMN IF EXISTS stream_id;
