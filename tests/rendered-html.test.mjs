import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { DashboardClient } from '../app/DashboardClient.tsx';
import { demoDashboard } from '../lib/demo-data.ts';
test('dashboard renders an honest empty intelligence view',()=>{
 const html=renderToStaticMarkup(createElement(DashboardClient,{initialData:demoDashboard}));
 assert.match(html,/Total Vulnerabilities/);assert.match(html,/Coverage &amp; Freshness/);
 assert.doesNotMatch(html,/CVE-2026-\d{4,}/);
});
