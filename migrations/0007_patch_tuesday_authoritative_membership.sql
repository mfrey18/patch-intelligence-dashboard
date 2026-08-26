ALTER TABLE `release_events` ADD COLUMN `reported_product_families_json` text;

-- VEX documents describe republished ecosystem/Linux vulnerabilities and are
-- not members of Microsoft's reported monthly Patch Tuesday CVE total.
DELETE FROM `release_event_advisories`
WHERE `advisory_id` IN (
  SELECT `id` FROM `advisories`
  WHERE `vendor_id` = 'microsoft' AND `vendor_advisory_id` LIKE 'vex:%'
);

-- Restore the canonical release-note URL if a later CSAF upsert overwrote it.
UPDATE `release_events`
SET `source_url` = (
  SELECT `a`.`source_url`
  FROM `release_event_advisories` `rea`
  JOIN `advisories` `a` ON `a`.`id` = `rea`.`advisory_id`
  WHERE `rea`.`release_event_id` = `release_events`.`id`
    AND `a`.`vendor_advisory_id` LIKE 'release-note:%'
  LIMIT 1
)
WHERE `vendor_id` = 'microsoft'
  AND `event_type` = 'patch_tuesday'
  AND EXISTS (
    SELECT 1 FROM `release_event_advisories` `rea`
    JOIN `advisories` `a` ON `a`.`id` = `rea`.`advisory_id`
    WHERE `rea`.`release_event_id` = `release_events`.`id`
      AND `a`.`vendor_advisory_id` LIKE 'release-note:%'
  );

-- Only sources in the validated production cadence participate in freshness
-- monitoring. Other authoritative adapters remain registered but fail closed
-- until they are deliberately promoted into this allowlist.
UPDATE `sources`
SET `enabled` = CASE WHEN `id` IN (
  'microsoft-msrc-csaf',
  'cisco-psirt-csaf',
  'cisa-kev',
  'first-epss',
  'palo-alto-psirt-csaf',
  'mozilla-mfsa-yaml'
) THEN 1 ELSE 0 END;

-- Older delta orchestration could leave a zero-width trailing checkpoint even
-- though no work remained. Close only that exact inert state.
UPDATE `ingestion_checkpoints`
SET `status` = 'complete', `updated_at` = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE `status` = 'pending' AND `window_start` = `window_end`;
