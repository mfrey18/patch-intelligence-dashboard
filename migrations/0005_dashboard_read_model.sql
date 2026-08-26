-- Expand-only dashboard read model. Canonical intelligence tables remain authoritative.
CREATE TABLE IF NOT EXISTS cve_dashboard_facts (
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

CREATE TABLE IF NOT EXISTS dashboard_projection_state (
  id TEXT PRIMARY KEY NOT NULL,
  projection_version INTEGER NOT NULL,
  generated_at TEXT NOT NULL,
  source_run_id TEXT,
  cve_count INTEGER NOT NULL,
  status TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dashboard_facts_priority_sort ON cve_dashboard_facts(priority, severity_rank DESC, epss_percentile DESC, published_at DESC, cve_id);
CREATE INDEX IF NOT EXISTS idx_dashboard_facts_severity_cvss ON cve_dashboard_facts(severity_rank, cvss);
CREATE INDEX IF NOT EXISTS idx_dashboard_facts_epss ON cve_dashboard_facts(epss_percentile);
CREATE INDEX IF NOT EXISTS idx_dashboard_facts_published ON cve_dashboard_facts(published_at);
CREATE INDEX IF NOT EXISTS idx_dashboard_facts_modified ON cve_dashboard_facts(modified_at);
CREATE INDEX IF NOT EXISTS idx_dashboard_facts_threat ON cve_dashboard_facts(kev, known_exploited, zero_day);

-- Join indexes used both by projection refresh and release-event analytics.
CREATE INDEX IF NOT EXISTS idx_affected_products_revision_cve_product ON affected_products(advisory_revision_id, cve_id, product_id);
CREATE INDEX IF NOT EXISTS idx_remediations_revision_cve_kind ON remediations(advisory_revision_id, cve_id, kind);
CREATE INDEX IF NOT EXISTS idx_release_events_type_date ON release_events(event_type, event_date DESC);
CREATE INDEX IF NOT EXISTS idx_release_event_advisories_advisory_event ON release_event_advisories(advisory_id, release_event_id);
