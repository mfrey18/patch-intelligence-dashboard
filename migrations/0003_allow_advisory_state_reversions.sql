-- A vendor advisory can legitimately return to a previously observed content
-- state after an intervening revision. The ingestion pipeline already suppresses
-- consecutive identical states by comparing the latest revision hash. Keeping
-- this index unique incorrectly rejects a material A -> B -> A transition.
DROP INDEX IF EXISTS `idx_advisory_revisions_advisory_hash`;
CREATE INDEX `idx_advisory_revisions_advisory_hash`
  ON `advisory_revisions` (`advisory_id`, `content_hash`);
