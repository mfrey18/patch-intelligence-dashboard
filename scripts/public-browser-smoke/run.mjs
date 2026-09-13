import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { chromium, expect } from '@playwright/test';

const pageUrl = new URL(process.env.PAGE_URL);
const apiOrigin = new URL(process.env.PUBLIC_API_BASE_URL).origin;
const localValidation = process.env.SMOKE_LOCAL_VALIDATION === 'true';
if (localValidation) {
  for (const url of [pageUrl, new URL(apiOrigin)]) {
    assert.equal(url.hostname, '127.0.0.1', 'Local validation is loopback only');
    assert.equal(url.protocol, 'http:');
  }
}
if (!localValidation) {
  assert.equal(pageUrl.href, 'https://mfrey18.github.io/patch-intelligence-dashboard/');
  assert.equal(apiOrigin, 'https://helperhavysmini.tail9d067e.ts.net');
  assert.equal(process.env.PUBLIC_VANTAGE, 'github-hosted-no-tailscale');
  assert.equal(process.env.GITHUB_ACTIONS, 'true');
}
const output = resolve(process.env.SMOKE_OUTPUT_DIR ?? 'work/public-browser-smoke');
await mkdir(output, { recursive: true });
const report = { startedAt: new Date().toISOString(), pageUrl: pageUrl.href, apiOrigin,
  vantage: localValidation ? 'local-validation-not-off-tailnet-proof' : process.env.PUBLIC_VANTAGE,
  workflowRunId: process.env.GITHUB_RUN_ID ?? null, pagesRunId: process.env.PAGES_WORKFLOW_RUN_ID ?? null,
  testedWorkflowSha: process.env.PAGES_WORKFLOW_SHA || process.env.GITHUB_SHA || null,
  status: 'running', checks: [], responses: [], pageErrors: [], requestFailures: [] };
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
await context.tracing.start({ screenshots: true, snapshots: true });
const page = await context.newPage();
page.setDefaultTimeout(30_000);
page.setDefaultNavigationTimeout(45_000);
const panels = ['activity', 'emerging', 'epss-movers', 'vendor-threats', 'cwe', 'products', 'patch-tuesday'];
let requestCount = 0;
const verifiedDownloadUrls = new Set();
// No write requests, private ports or unexpected API origin may leave this browser.
await context.route('**/*', async (route) => {
  const request = route.request();
  const url = new URL(request.url());
  if (url.pathname.startsWith('/api/')) requestCount += 1;
  if (![pageUrl.origin, apiOrigin].includes(url.origin) || request.method() !== 'GET' ||
      (url.pathname.startsWith('/api/') && url.origin !== apiOrigin) || requestCount > 180) {
    report.requestFailures.push({ url: url.href, reason: 'Approved origins, GET method or 180-request budget violation' });
    await route.abort();
    return;
  }
  await route.continue();
});
page.on('pageerror', (error) => report.pageErrors.push(error.message));
page.on('requestfailed', (request) => report.requestFailures.push({ url: request.url(), reason: request.failure()?.errorText }));
page.on('response', (response) => {
  const url = new URL(response.url());
  if (url.pathname.startsWith('/api/')) report.responses.push({ url: response.url(), status: response.status(), at: new Date().toISOString() });
});
const deadline = setTimeout(() => { report.error = 'Eight-minute browser budget exceeded'; void browser.close(); }, 8 * 60_000);
function checked(name, details = {}) { report.checks.push({ name, ...details, passed: true }); }
async function screenshot(name) { await page.screenshot({ path: resolve(output, `${name}.png`), fullPage: true }); }
async function dashboardAction(name, action, validate = () => {}) {
  const started = performance.now();
  const pending = ['/api/dashboard', ...panels.map((panel) => `/api/dashboard/analytics/${panel}`)].map((path) =>
    page.waitForResponse((response) => new URL(response.url()).origin === apiOrigin && new URL(response.url()).pathname === path));
  const [responses] = await Promise.all([Promise.all(pending), action()]);
  for (const response of responses) {
    assert.equal(response.status(), 200, `${name}: ${response.url()}`);
    if (pageUrl.origin !== apiOrigin) assert.equal(await response.headerValue('access-control-allow-origin'), pageUrl.origin, 'Browser CORS origin');
  }
  const core = await responses[0].json();
  assert.equal(core.demo, false, 'Must display production data, not demo');
  validate(core);
  await expect(page.locator('#overview')).toHaveAttribute('aria-busy', 'false');
  await expect(page.locator('#vulnerabilities tbody tr')).toHaveCount(core.rows.length);
  if (core.rows.length) await expect(page.locator('#vulnerabilities tbody tr').first()).toContainText(core.rows[0].cveId);
  checked(name, { total: core.metrics.total, rows: core.rows.length, elapsedMs: Math.round(performance.now() - started) });
  return core;
}
try {
  const base = await dashboardAction('public load and all seven analytics panels', () => page.goto(pageUrl.href),
    (data) => assert.ok(data.metrics.total > 0 && data.rows.length >= 2));
  await expect(page.getByText('Representative preview data', { exact: true })).toHaveCount(0);
  await screenshot('01-dashboard');
  if (base.nextCursor) {
    const second = await dashboardAction('pagination', () => page.getByRole('button', { name: 'Load more vulnerabilities', exact: true }).click());
    assert.ok(second.rows.every((row) => !base.rows.some((first) => first.cveId === row.cveId)), 'Adjacent pages overlap');
  }
  const cisco = await dashboardAction('Cisco vendor filter', () => page.getByRole('combobox', { name: 'Vendor', exact: true }).selectOption('cisco'),
    (data) => assert.ok(data.rows.length && data.rows.every((row) => /cisco/i.test(row.vendor))));
  const selected = cisco.rows[0];
  await dashboardAction('combined vendor and severity filter', () => page.getByRole('combobox', { name: 'Severity', exact: true }).selectOption(selected.severity),
    (data) => assert.ok(data.rows.length && data.rows.every((row) => /cisco/i.test(row.vendor) && row.severity === selected.severity)));
  await dashboardAction('filter persistence after reload', () => page.reload(),
    (data) => assert.ok(data.rows.every((row) => /cisco/i.test(row.vendor) && row.severity === selected.severity)));
  await expect(page.getByRole('combobox', { name: 'Vendor', exact: true })).toHaveValue('cisco');
  await dashboardAction('exact CVE search', async () => {
    await page.getByRole('textbox', { name: 'Search CVE, vendor, or product', exact: true }).fill(selected.cveId.toLowerCase());
    await page.getByRole('button', { name: 'Search', exact: true }).click();
  }, (data) => assert.deepEqual(data.rows.map((row) => row.cveId), [selected.cveId]));
  await screenshot('02-filtered');

  const csvPromise = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Export CSV · 1,000 max', exact: true }).click();
  const csv = await csvPromise;
  assert.equal(await csv.failure(), null);
  await csv.saveAs(resolve(output, 'filtered-export.csv'));
  const csvText = await readFile(resolve(output, 'filtered-export.csv'), 'utf8');
  assert.ok(csvText.startsWith('cve_id,priority,priority_reasons,'));
  assert.ok(csvText.includes(selected.cveId));
  verifiedDownloadUrls.add(csv.url());
  checked('real CSV download for filtered CVE', { filename: csv.suggestedFilename() });

  const jsonPromise = page.waitForResponse((response) => new URL(response.url()).pathname === '/api/dashboard/export' && new URL(response.url()).searchParams.get('format') === 'json');
  await page.getByRole('link', { name: 'Export JSON · 1,000 max', exact: true }).click();
  const jsonResponse = await jsonPromise;
  assert.equal(jsonResponse.status(), 200);
  assert.match(await jsonResponse.headerValue('content-type'), /application\/json/);
  const exported = await jsonResponse.json();
  assert.deepEqual(exported.rows.map((row) => row.cveId), [selected.cveId]);
  assert.equal(typeof exported.rows[0].kev, 'boolean');
  await writeFile(resolve(output, 'filtered-export.json'), JSON.stringify(exported, null, 2));
  checked('real JSON export navigation and typed data');
  await dashboardAction('return from export', () => page.goBack());

  const detailPromise = page.waitForResponse((response) => new URL(response.url()).pathname === `/api/cves/${selected.cveId}`);
  await page.locator('#vulnerabilities tbody').getByRole('link', { name: selected.cveId, exact: true }).click();
  const detailResponse = await detailPromise;
  assert.equal(detailResponse.status(), 200);
  const detail = await detailResponse.json();
  assert.equal(detail.canonical.cveId, selected.cveId);
  assert.ok(detail.advisories.length && detail.sourceLinks.length, 'Selected vendor CVE must preserve provenance');
  await expect(page.getByRole('heading', { name: selected.cveId, exact: true })).toBeVisible();
  for (const title of ['Vulnerability Identity', 'Vendor Advisories & Affected Products', 'EPSS Trend', 'Authoritative Source Correlation', 'Intelligence Timeline', 'Vendor Remediation Information']) {
    await expect(page.getByRole('heading', { name: title, exact: true })).toBeVisible();
  }
  await screenshot('03-detail');
  checked('CVE detail and provenance', { cveId: selected.cveId, sourceLinks: detail.sourceLinks.length });
  await dashboardAction('return from detail', () => page.getByRole('link', { name: '← Dashboard', exact: true }).click());
  await dashboardAction('clear filters', () => page.getByRole('button', { name: 'Clear filters', exact: true }).click(),
    (data) => assert.ok(data.metrics.total > 0 && data.rows.length >= 2));
  await dashboardAction('Microsoft vendor filter', () => page.getByRole('combobox', { name: 'Vendor', exact: true }).selectOption('microsoft'),
    (data) => assert.ok(data.rows.length && data.rows.every((row) => /microsoft/i.test(row.vendor))));
  await dashboardAction('honest empty search state', async () => {
    await page.getByRole('textbox', { name: 'Search CVE, vendor, or product', exact: true }).fill('CVE-1900-999999999');
    await page.getByRole('button', { name: 'Search', exact: true }).click();
  }, (data) => assert.equal(data.metrics.total, 0));
  await screenshot('04-empty-state');

  // Excluded routes intentionally omit CORS; inspect their HTTP status outside page JS.
  // These requests still originate on this unauthenticated, public-only runner.
  const access = [];
  for (const path of ['/api/internal/health', '/api/internal/monitor']) {
    const response = await context.request.get(apiOrigin + path, { timeout: 30_000 });
    access.push({ path, status: response.status() });
  }
  assert.ok(access.every((entry) => entry.status === 404));
  checked('public internal routes excluded', { results: access });
  assert.deepEqual(report.pageErrors, [], 'Browser JavaScript errors');
  // Chromium cancels the document navigation when a response becomes a download.
  // Exempt only the exact URL whose actual file was saved and validated above.
  report.downloadNavigationAborts = report.requestFailures.filter((entry) =>
    entry.reason === 'net::ERR_ABORTED' && verifiedDownloadUrls.has(entry.url));
  const unexpectedFailures = report.requestFailures.filter((entry) => !report.downloadNavigationAborts.includes(entry));
  assert.deepEqual(unexpectedFailures, [], 'Browser network errors');
  assert.ok(report.responses.every((entry) => entry.status === 200 || (new URL(entry.url).pathname.startsWith('/api/internal/') && entry.status === 404)), 'Unexpected API failure');
  report.status = 'passed';
} catch (error) {
  report.status = 'failed';
  report.error = error.stack ?? String(error);
  await screenshot('failure').catch(() => {});
  process.exitCode = 1;
} finally {
  clearTimeout(deadline);
  report.completedAt = new Date().toISOString();
  report.apiRequestCount = requestCount;
  await context.tracing.stop({ path: resolve(output, 'trace.zip') }).catch(() => {});
  await browser.close();
  await writeFile(resolve(output, 'report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ status: report.status, checks: report.checks.length, apiRequests: requestCount, evidence: output }));
}
