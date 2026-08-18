DROP INDEX IF EXISTS idx_click_events_short_url_id_browser;
DROP INDEX IF EXISTS idx_click_events_short_url_id_os;
ALTER TABLE click_events DROP COLUMN browser;
ALTER TABLE click_events DROP COLUMN os;
