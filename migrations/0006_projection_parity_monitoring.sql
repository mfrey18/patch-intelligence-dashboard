-- Expand-only staging and audit fields for fail-closed projection publication.
CREATE TABLE IF NOT EXISTS cve_dashboard_facts_staging (
  cve_id TEXT PRIMARY KEY NOT NULL REFERENCES cves(id),
  title TEXT NOT NULL,
  vendor TEXT NOT NULL,
  vendor_ids TEXT NOT NULL,
  product TEXT,
  severity_rank INTEGER NOT NULL,
  cvss REAL,
  epss REAL,
  epss_percentile REAL,
  kev INTEGER NOT NULL,
  known_exploited INTEGER NOT NULL,
  zero_day INTEGER NOT NULL,
  patch_available INTEGER,
  mitigation_available INTEGER NOT NULL,
  workaround_available INTEGER NOT NULL,
  published_at TEXT,
  modified_at TEXT,
  cwe TEXT,
  priority TEXT NOT NULL,
  projected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dashboard_projection_leases (
  id TEXT PRIMARY KEY NOT NULL,
  holder TEXT NOT NULL,
  acquired_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

ALTER TABLE dashboard_projection_state ADD COLUMN parity_checked_at TEXT;
ALTER TABLE dashboard_projection_state ADD COLUMN parity_status TEXT;
ALTER TABLE dashboard_projection_state ADD COLUMN parity_json TEXT;
ALTER TABLE dashboard_projection_state ADD COLUMN last_attempt_at TEXT;
ALTER TABLE dashboard_projection_state ADD COLUMN last_attempt_status TEXT;
ALTER TABLE dashboard_projection_state ADD COLUMN last_attempt_error TEXT;
