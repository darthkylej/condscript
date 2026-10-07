-- Live meeting log: concurrent notes, testimony observations, and resumable talk timing

CREATE TABLE IF NOT EXISTS meeting_log_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  meeting_id uuid NOT NULL REFERENCES meetings(id) ON DELETE CASCADE,
  entry_type text NOT NULL CHECK (entry_type IN ('note','timestamp','testimony','topic')),
  label text,
  value text,
  normalized_value text,
  occurred_at timestamptz NOT NULL DEFAULT NOW(),
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_meeting_log_entries_meeting_time
  ON meeting_log_entries (meeting_id, occurred_at, created_at);

CREATE TABLE IF NOT EXISTS meeting_talk_segments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  meeting_id uuid NOT NULL REFERENCES meetings(id) ON DELETE CASCADE,
  speaker_key text NOT NULL,
  speaker_name text NOT NULL,
  started_at timestamptz NOT NULL DEFAULT NOW(),
  ended_at timestamptz,
  started_by uuid REFERENCES users(id),
  ended_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT NOW(),
  CHECK (ended_at IS NULL OR ended_at >= started_at)
);

CREATE INDEX IF NOT EXISTS idx_meeting_talk_segments_meeting
  ON meeting_talk_segments (meeting_id, speaker_key, started_at);

CREATE UNIQUE INDEX IF NOT EXISTS uq_meeting_talk_one_active_segment
  ON meeting_talk_segments (meeting_id, speaker_key)
  WHERE ended_at IS NULL;
