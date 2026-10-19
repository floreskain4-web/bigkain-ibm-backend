import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const load = name => readFileSync(new URL(`../site/${name}`, import.meta.url), 'utf8');
const data = JSON.parse(load('rocket-q2-2026.json'));
const html = load('index.html');

test('Rocket Q2 2026 snapshot preserves reported values and USD units', () => {
  assert.equal(data.currency, 'USD');
  assert.equal(data.periodEnd, '2026-06-30');
  assert.deepEqual(data.metrics, {
    totalRevenueNet: 2784000000,
    adjustedRevenue: 2761000000,
    netIncome: 229000000,
    adjustedNetIncome: 441000000,
    adjustedEbitda: 766000000,
    adjustedDilutedEps: 0.16,
  });
  for (const value of ['$2.784B', '$2.761B', '$229M', '$441M', '$766M', '$0.16']) {
    assert.ok(html.includes(`<strong>${value}</strong>`));
  }
});

test('Historical company results are separated from live Bitcoin data', () => {
  assert.ok(html.includes('id="company-financials"'));
  assert.ok(html.includes('id="market-flow"'));
  assert.ok(html.includes('id="service-status"'));
  assert.ok(html.includes('not BigKain revenue, wallet balances, or Bitcoin market flows'));
  assert.ok(html.includes('This historical snapshot does not refresh with the live feeds.'));
  assert.ok(html.includes('company-defined non-GAAP'));
  assert.ok(html.includes('Unaudited'));
  assert.ok(html.includes('does not sign transactions'));
});

test('Outlook remains company guidance with traceable sources', () => {
  assert.equal(data.outlook.period, 'Q3 2026');
  assert.equal(data.outlook.low, 2500000000);
  assert.equal(data.outlook.high, 2700000000);
  assert.match(data.outlook.source, /not the workbook/);
  assert.match(data.sources.sha256, /^[a-f0-9]{64}$/);
  assert.ok(html.includes(data.sources.earningsRelease));
  assert.ok(html.includes('Company guidance from the earnings release, not an actual result'));
});
