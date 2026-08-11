-- cmd/workerはRedis Stream("clicks")をconsumer groupで読み取り、
-- at-least-once配送(6節-5)を前提にclick_eventsへ書き込む。冪等キーとして
-- Redis Streamのエントリ ID(例: "1691568000000-0"、ストリーム内で一意)を
-- 保持し、再配送された同一エントリの二重INSERTをON CONFLICTで防ぐ。
--
-- パーティション化テーブルの一意インデックスはパーティションキー
-- (clicked_at)を含む必要があるため、UNIQUE(clicked_at, stream_id)とする。
ALTER TABLE click_events ADD COLUMN stream_id text NOT NULL;

CREATE UNIQUE INDEX idx_click_events_clicked_at_stream_id ON click_events (clicked_at, stream_id);
