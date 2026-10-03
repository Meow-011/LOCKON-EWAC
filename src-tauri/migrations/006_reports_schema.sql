CREATE TABLE IF NOT EXISTS intel_reports (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  target_name TEXT NOT NULL,
  timestamp INTEGER NOT NULL,
  total_nodes INTEGER,
  critical_nodes INTEGER,
  total_aps INTEGER,
  vulnerable_aps INTEGER,
  raw_data TEXT NOT NULL
);
