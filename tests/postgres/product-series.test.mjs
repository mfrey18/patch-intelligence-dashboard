import { test } from 'node:test';
import assert from 'node:assert/strict';
import { testDatabase } from './database.mjs';
import { seedIngestionCatalog } from '../../lib/ingestion/postgres-repository.ts';
import { queryDashboardAnalytics, queryPatchTuesdayEvents } from '../../lib/api/dashboard-query.ts';

test('product series uses current revisions, expands advisory-wide products and counts distinct filtered CVEs', async () => {
  const db = await testDatabase();
  try {
    await seedIngestionCatalog(db);
    const cves = ['CVE-2026-1001', 'CVE-2026-1002', 'CVE-2026-1003'];
    for (const cve of cves) {
      await db.prepare('INSERT INTO cves(id,published_at,created_at,updated_at) VALUES (?,now(),now(),now())').bind(cve).run();
    }
    for (const [id, vendor, source, linked] of [
      ['a', 'microsoft', 'microsoft-msrc-csaf', [0, 1]],
      ['b', 'microsoft', 'microsoft-msrc-csaf', [1]],
      ['c', 'palo-alto', 'palo-alto-psirt-csaf', [1, 2]],
    ]) {
      await db.prepare(`INSERT INTO advisories(id,vendor_id,source_id,vendor_advisory_id,title,source_url,published_at,created_at,updated_at)
        VALUES (?,?,?,?,?,'https://vendor.example/advisory',now(),now(),now())`).bind(id, vendor, source, 'advisory:' + id, 'Advisory ' + id).run();
      for (const index of linked) {
        await db.prepare("INSERT INTO advisory_cves(advisory_id,cve_id,normalized_severity) VALUES (?,?,'high')").bind(id, cves[index]).run();
      }
    }
    for (const [id, advisory, age] of [
      ['a-old', 'a', 2], ['a-current-a', 'a', 1], ['a-current-z', 'a', 1],
      ['b-current', 'b', 1], ['c-current', 'c', 1],
    ]) {
      await db.prepare(`INSERT INTO advisory_revisions(id,advisory_id,observed_at,content_hash,affected_products_hash,remediation_hash,exploitation_status,change_types_json,normalized_json,source_url)
        VALUES (?,?,date_trunc('day',now())-?*INTERVAL '1 day',?,'products','remediation','not_known_exploited','[]','{}','https://vendor.example/advisory')`).bind(id, advisory, age, id).run();
    }
    for (const [id, name, family] of [
      ['alpha-1', 'Alpha one', 'Alpha'], ['alpha-2', 'Alpha two', 'Alpha'],
      ['beta', 'Beta', null], ['delta', 'Delta', null], ['lowercase', 'alpha', null],
      ['old', 'Old revision only', null], ['losing-tie', 'Losing revision tie', null],
      ['unlinked', 'Unlinked CVE product', null], ['zeta', 'Zeta', null],
    ]) {
      await db.prepare("INSERT INTO products(id,vendor_id,name,family,created_at,updated_at) VALUES (?,'microsoft',?,?,now(),now())").bind(id, name, family).run();
    }
    let assertion = 0;
    for (const [advisory, revision, cve, product] of [
      ['a', 'a-old', cves[0], 'old'],
      ['a', 'a-current-a', cves[0], 'losing-tie'],
      ['a', 'a-current-z', cves[0], 'alpha-1'],
      ['a', 'a-current-z', cves[0], 'alpha-1'], // Two affected versions must count once.
      ['a', 'a-current-z', null, 'alpha-2'], // Applies to both CVEs linked to advisory a.
      ['a', 'a-current-z', cves[1], 'beta'],
      ['a', 'a-current-z', cves[0], 'lowercase'],
      ['a', 'a-current-z', cves[0], 'zeta'],
      ['a', 'a-current-z', cves[2], 'unlinked'], // A foreign CVE is not linked to advisory a.
      ['b', 'b-current', cves[1], 'alpha-1'], // Shared CVE across advisories must count once.
      ['c', 'c-current', cves[2], 'alpha-1'],
      ['c', 'c-current', null, 'delta'],
    ]) {
      await db.prepare("INSERT INTO affected_products(id,advisory_id,advisory_revision_id,cve_id,product_id,status) VALUES (?,?,?,?,?,'affected')").bind('assertion-' + assertion++, advisory, revision, cve, product).run();
    }
    const products = async (query = '') => (await queryDashboardAnalytics(db, new URL('https://test/api/dashboard?' + query), 'products')).productSeries;
    const expected = { Alpha: 3, Delta: 2, Beta: 1, alpha: 1, Zeta: 1 };
    const canonical = await products();
    assert.deepEqual(Object.fromEntries(canonical.map(row => [row.label, row.value])), expected);
    assert.deepEqual(canonical.slice(0, 2), [{ label: 'Alpha', value: 3 }, { label: 'Delta', value: 2 }]);
    assert.ok(canonical.findIndex(row => row.label === 'Beta') < canonical.findIndex(row => row.label === 'Zeta'));
    assert.ok(canonical.every(row => typeof row.value === 'number'));
    assert.deepEqual(Object.fromEntries((await products('vendor=microsoft')).map(row => [row.label, row.value])), { Alpha: 2, Beta: 1, alpha: 1, Zeta: 1 });
    assert.deepEqual(await products('vendor=palo-alto'), [{ label: 'Delta', value: 2 }, { label: 'Alpha', value: 1 }]);
    assert.deepEqual(Object.fromEntries((await products('q=CVE-2026-1003')).map(row => [row.label, row.value])), { Alpha: 1, Delta: 1 });
    assert.deepEqual(await products('q=no-matching-cve'), []);

    // Release families also count CVEs once across duplicated versions,
    // advisory-wide assertions, and multiple linked advisories. A second event
    // sharing an advisory retains its own count, and older revisions stay out.
    for (const [id, date, advisories] of [
      ['current-event', '2026-09-08', ['a', 'b']],
      ['previous-event', '2026-08-11', ['b']],
    ]) {
      await db.prepare(`INSERT INTO release_events(id,vendor_id,event_type,event_date,label,created_at,updated_at)
        VALUES (?,'microsoft','patch_tuesday',?,?,now(),now())`).bind(id, date, id).run();
      for (const advisory of advisories) {
        await db.prepare('INSERT INTO release_event_advisories(release_event_id,advisory_id) VALUES (?,?)').bind(id, advisory).run();
      }
    }
    const [currentEvent, previousEvent] = await queryPatchTuesdayEvents(db);
    assert.deepEqual(Object.fromEntries(currentEvent.linkedProductFamilies.map(row => [row.label, row.value])), { Alpha: 2, Beta: 1, alpha: 1, Zeta: 1 });
    assert.deepEqual(previousEvent.linkedProductFamilies, [{ label: 'Alpha', value: 1 }]);
    assert.deepEqual((await queryPatchTuesdayEvents(db, 1))[0].linkedProductFamilies, currentEvent.linkedProductFamilies);

    // Exercise the same query with the published projection's independently built
    // filtered CTE; the current product relation must preserve identical results.
    for (const [index, cve] of cves.entries()) {
      const vendors = index === 0 ? '|microsoft|' : index === 1 ? '|microsoft|palo-alto|' : '|palo-alto|';
      await db.prepare(`INSERT INTO cve_dashboard_facts(cve_id,title,vendor,vendor_ids,severity_rank,kev,known_exploited,zero_day,mitigation_available,workaround_available,priority,projected_at)
        VALUES (?,?,'Microsoft, Palo Alto',?,3,FALSE,FALSE,FALSE,FALSE,FALSE,'P3',now())`).bind(cve, cve, vendors).run();
    }
    await db.prepare("INSERT INTO dashboard_projection_state(id,projection_version,generated_at,cve_count,status) VALUES ('current',1,now(),3,'published')").run();
    assert.deepEqual(await products(), canonical);
    assert.deepEqual(Object.fromEntries((await products('vendor=microsoft')).map(row => [row.label, row.value])), { Alpha: 2, Beta: 1, alpha: 1, Zeta: 1 });
    assert.deepEqual(await products('vendor=palo-alto'), [{ label: 'Delta', value: 2 }, { label: 'Alpha', value: 1 }]);
    assert.deepEqual(Object.fromEntries((await products('q=CVE-2026-1003')).map(row => [row.label, row.value])), { Alpha: 1, Delta: 1 });
    for (let index = 1; index <= 14; index++) {
      const label = 'Limit' + String(index).padStart(2, '0');
      await db.prepare("INSERT INTO products(id,vendor_id,name,created_at,updated_at) VALUES (?,'palo-alto',?,now(),now())").bind(label, label).run();
      await db.prepare("INSERT INTO affected_products(id,advisory_id,advisory_revision_id,cve_id,product_id,status) VALUES (?,'c','c-current',?,?,'affected')").bind(label, cves[2], label).run();
    }
    assert.deepEqual(await products('q=CVE-2026-1003'), ['Alpha', 'Delta', ...Array.from({ length: 10 }, (_, index) => 'Limit' + String(index + 1).padStart(2, '0'))].map(label => ({ label, value: 1 })));
  } finally {
    await db.close();
  }
});
