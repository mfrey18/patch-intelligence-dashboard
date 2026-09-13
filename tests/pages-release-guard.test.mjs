import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { requireId, requirePublicOrigin, requireSha, requireSuccessfulJobs, verifyRollbackArtifact, verifyRun } from '../scripts/pages-release-guard.mjs';

const sha = 'a'.repeat(40);
const repository = 'owner/dashboard';
const native = {
  repository: { full_name: repository }, head_repository: { full_name: repository },
  path: '.github/workflows/native.yml', head_branch: 'main', head_sha: sha,
  event: 'workflow_dispatch', status: 'completed', conclusion: 'success',
};
const expected = { repository, workflow: 'native.yml', sha, events: ['push', 'workflow_dispatch'] };
const jobs = ['validate', 'deploy'].map(name => ({ name, status: 'completed', conclusion: 'success' }));

test('Pages requires successful main-native provenance and the exact selected SHA', () => {
  verifyRun(native, expected);
  requireSuccessfulJobs(jobs, ['validate', 'deploy']);
  for (const mutation of [
    { head_sha: 'b'.repeat(40) }, { head_branch: 'feature' }, { event: 'pull_request' },
    { status: 'in_progress' }, { conclusion: 'failure' }, { path: '.github/workflows/other.yml' },
    { repository: { full_name: 'other/repo' } }, { head_repository: { full_name: 'fork/dashboard' } },
  ]) assert.throws(() => verifyRun({ ...native, ...mutation }, expected));
});

test('a successful validation-only run or skipped deployment cannot publish Pages', () => {
  for (const conclusion of ['skipped', 'failure', 'cancelled', null]) {
    assert.throws(() => requireSuccessfulJobs([jobs[0], { ...jobs[1], conclusion }], ['validate', 'deploy']));
  }
  assert.throws(() => requireSuccessfulJobs([jobs[0]], ['validate', 'deploy']));
  assert.throws(() => requireSuccessfulJobs([...jobs, jobs[1]], ['validate', 'deploy']));
});

test('rollback preparation accepts only the pinned successful Pages source', () => {
  const run = { ...native, path: '.github/workflows/pages.yml', event: 'workflow_run' };
  const criteria = { ...expected, workflow: 'pages.yml', events: ['workflow_run', 'workflow_dispatch'] };
  verifyRun(run, criteria);
  requireSuccessfulJobs(['build', 'deploy'].map(name => ({ name, status: 'completed', conclusion: 'success' })), ['build', 'deploy']);
  assert.throws(() => verifyRun(native, criteria));
});

test('rollback artifacts must match both immutable IDs and the pinned source, and remain available', () => {
  const artifact = { id: 123, workflow_run: { id: 456 }, name: `pages-rollback-${sha}`, expired: false, size_in_bytes: 100 };
  const criteria = { artifactId: '123', runId: '456', sha };
  verifyRollbackArtifact(artifact, criteria);
  for (const mutation of [
    { id: 124 }, { workflow_run: { id: 457 } }, { name: `pages-rollback-${'b'.repeat(40)}` },
    { expired: true }, { size_in_bytes: 0 },
  ]) assert.throws(() => verifyRollbackArtifact({ ...artifact, ...mutation }, criteria));
});

test('IDs, hashes and rollback origin reject ambiguous or injected inputs', () => {
  requireId('123'); requireSha(sha); requirePublicOrigin('https://legacy.example.com');
  for (const value of ['0', '-1', '1\noutput=x', '9e2', '9007199254740992']) assert.throws(() => requireId(value));
  for (const value of ['main', 'a'.repeat(7), `${sha}\n`, `${sha}\noutput=x`]) assert.throws(() => requireSha(value));
  for (const value of ['http://example.com', 'https://user:secret@example.com', 'https://example.com/path', 'https://example.com/']) assert.throws(() => requirePublicOrigin(value));
});

test('normal and rollback workflows retain distinct gates and protected deployment', () => {
  const normal = readFileSync(new URL('../.github/workflows/pages.yml', import.meta.url), 'utf8');
  const rollback = readFileSync(new URL('../.github/workflows/pages-rollback.yml', import.meta.url), 'utf8');
  assert.match(normal, /vars\.DATABASE_BACKEND == 'postgres'/);
  assert.match(normal, /pages-release-guard\.mjs native/);
  assert.match(normal, /native_run_id:/);
  assert.match(rollback, /default: prepare/);
  assert.match(rollback, /pages-release-guard\.mjs artifact/);
  assert.match(rollback, /sha256sum --check --strict/);
  assert.match(rollback, /needs: stage-restore/);
  assert.match(rollback, /name: github-pages/);
  assert.doesNotMatch(rollback, /DATABASE_BACKEND|ENABLE_NATIVE_DEPLOYMENT|INGEST_SECRET|tailscale\/|cloudflare\/|db:migrate/);
});
