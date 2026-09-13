import assert from 'node:assert/strict';
import { appendFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export function requireSha(value) {
  assert.ok(typeof value === 'string' && value.length === 40 && /^[a-f0-9]{40}$/.test(value), 'A full lowercase commit SHA is required');
  return value;
}

export function requireId(value) {
  assert.match(String(value ?? ''), /^[1-9][0-9]*$/, 'A positive GitHub run/artifact ID is required');
  assert.ok(Number.isSafeInteger(Number(value)), 'GitHub ID is out of range');
  return Number(value);
}

export function verifyRun(run, { repository, workflow, sha, events }) {
  assert.equal(run.repository?.full_name, repository, 'Run belongs to another repository');
  assert.equal(run.head_repository?.full_name, repository, 'Fork runs cannot deploy production Pages');
  assert.equal(run.path, `.github/workflows/${workflow}`, 'Unexpected source workflow');
  assert.equal(run.head_branch, 'main', 'Only main runs are eligible');
  if (sha) assert.equal(run.head_sha, requireSha(sha), 'Run SHA does not match the selected release');
  assert.ok(events.includes(run.event), 'Unexpected source run event');
  assert.equal(run.status, 'completed', 'Source run is still active');
  assert.equal(run.conclusion, 'success', 'Source run did not succeed');
}

export function requireSuccessfulJobs(jobs, names) {
  for (const name of names) {
    const matching = jobs.filter(job => job.name === name);
    assert.equal(matching.length, 1, `Expected exactly one ${name} job`);
    assert.equal(matching[0].status, 'completed', `${name} job is still active`);
    assert.equal(matching[0].conclusion, 'success', `${name} job did not run successfully`);
  }
}

export function verifyRollbackArtifact(artifact, { runId, sha, artifactId }) {
  assert.equal(artifact.id, requireId(artifactId), 'Unexpected artifact ID');
  assert.equal(artifact.workflow_run?.id, requireId(runId), 'Artifact belongs to another run');
  assert.equal(artifact.name, `pages-rollback-${requireSha(sha)}`, 'Artifact does not identify the pinned source SHA');
  assert.equal(artifact.expired, false, 'Rollback artifact has expired');
  assert.ok(artifact.size_in_bytes > 0, 'Rollback artifact is empty');
}

export function requirePublicOrigin(value) {
  const url = new URL(value);
  assert.equal(url.protocol, 'https:', 'Rollback API must use HTTPS');
  assert.ok(url.origin === value, 'Supply only the public API origin, without credentials, path or trailing slash');
  return value;
}

async function main() {
  const mode = process.argv[2];
  const repository = process.env.GITHUB_REPOSITORY;
  assert.match(repository ?? '', /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/);
  const token = process.env.GITHUB_TOKEN;
  assert.ok(token, 'Read-only GitHub token is required');
  const get = async path => {
    const response = await fetch(`https://api.github.com/repos/${repository}/${path}`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' },
      signal: AbortSignal.timeout(30000), redirect: 'error',
    });
    assert.ok(response.ok, `GitHub metadata request failed with HTTP ${response.status}`);
    return response.json();
  };
  const runId = requireId(process.env.SOURCE_RUN_ID);
  const sha = requireSha(process.env.SOURCE_SHA);
  const run = await get(`actions/runs/${runId}`);
  const jobs = [];
  for (let page = 1; page <= 10; page++) {
    const batch = await get(`actions/runs/${runId}/jobs?filter=latest&per_page=100&page=${page}`);
    jobs.push(...batch.jobs);
    if (jobs.length >= batch.total_count) break;
    assert.ok(page < 10, 'Too many jobs to validate safely');
  }
  if (mode === 'native') {
    verifyRun(run, { repository, workflow: 'native.yml', sha, events: ['push', 'workflow_dispatch'] });
    requireSuccessfulJobs(jobs, ['validate', 'deploy']);
  } else if (mode === 'legacy') {
    verifyRun(run, { repository, workflow: 'pages.yml', sha, events: ['workflow_run', 'workflow_dispatch'] });
    requireSuccessfulJobs(jobs, ['build', 'deploy']);
    requirePublicOrigin(process.env.LEGACY_API_ORIGIN);
  } else if (mode === 'artifact') {
    verifyRun(run, { repository, workflow: 'pages-rollback.yml', events: ['workflow_dispatch'] });
    requireSuccessfulJobs(jobs, ['prepare']);
    const artifactId = requireId(process.env.ROLLBACK_ARTIFACT_ID);
    verifyRollbackArtifact(await get(`actions/artifacts/${artifactId}`), { runId, sha, artifactId });
    assert.match(process.env.ROLLBACK_TAR_SHA256 ?? '', /^[a-f0-9]{64}$/, 'Pinned artifact.tar SHA-256 is required');
  } else {
    throw new Error('Expected native, legacy or artifact mode');
  }
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `source_sha=${sha}\n`);
  console.log(JSON.stringify({ status: 'passed', mode, runId, sourceSha: sha }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
