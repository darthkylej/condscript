ALTER TABLE meetings
  ADD COLUMN IF NOT EXISTS meeting_time time,
  ADD COLUMN IF NOT EXISTS location text;

ALTER TABLE meetings
  DROP CONSTRAINT IF EXISTS meetings_ward_id_meeting_date_key;

CREATE INDEX IF NOT EXISTS meetings_ward_date_time_idx
  ON meetings (ward_id, meeting_date DESC, meeting_time);
