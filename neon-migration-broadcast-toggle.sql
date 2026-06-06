ALTER TABLE meetings
  ADD COLUMN IF NOT EXISTS is_broadcast boolean NOT NULL DEFAULT true;
