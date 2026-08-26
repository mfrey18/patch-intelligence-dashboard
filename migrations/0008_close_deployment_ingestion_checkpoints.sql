-- Deployment validation previously created resumable Microsoft checkpoints.
-- Ingestion is now isolated in ingestion.yml, and subsequent source runs have
-- reconciled these windows. Preserve the audit rows while closing only pending
-- checkpoints owned by the retired deployment conventions.
UPDATE ingestion_checkpoints
SET status = 'complete',
    continuation_token = NULL,
    updated_at = CURRENT_TIMESTAMP
WHERE status = 'pending'
  AND (
    id LIKE 'gate1:microsoft:%'
    OR id LIKE 'deploy:release-note:%'
  );
