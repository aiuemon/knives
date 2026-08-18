-- OS・ブラウザ別の統計(4節)のため、click_events取り込み時
-- (cmd/worker)にUser-Agentから解析したカテゴリを保存する。referrer_host
-- と同じ考え方: 生の文字列(user_agent_raw)自体は既にあるが、集計の
-- たびに毎回パースするのは非効率なため、取り込み時に一度だけ解析して
-- 列に持たせる。
ALTER TABLE click_events ADD COLUMN os text;
ALTER TABLE click_events ADD COLUMN browser text;

CREATE INDEX idx_click_events_short_url_id_os ON click_events (short_url_id, os);
CREATE INDEX idx_click_events_short_url_id_browser ON click_events (short_url_id, browser);
