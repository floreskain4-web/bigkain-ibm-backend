import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import app from '../server.js';
import {
  calculateFlowSignal,
  FARSIDE_BTC_ALL_DATA_URL,
  FARSIDE_FETCH_URL,
  parseFarsideSessions,
  summarizeEtfFlows,
} from '../market.js';

const FARSIDE_FIXTURE = `
<table>
  <thead><tr><th>Date</th><th>IBIT</th><th>FBTC</th><th>GBTC</th><th>Total</th></tr></thead>
  <tbody>
    <tr><td>28 Sep 2026</td><td>54.8</td><td>(10.9)</td><td>(23.2)</td><td>31.0</td></tr>
    <tr><td>29 Sep 2026</td><td>51.1</td><td>0.0</td><td>0.0</td><td>66.2</td></tr>
    <tr><td>30 Sep 2026</td><td>(9.5)</td><td>(125.6)</td><td>0.0</td><td>(148.7)</td></tr>
    <tr><td>01 Oct 2026</td><td>195.6</td><td>(60.7)</td><td>(31.4)</td><td>102.7</td></tr>
    <tr><td>02 Oct 2026</td><td>158.2</td><td>29.3</td><td>0.0</td><td>189.9</td></tr>
    <tr><td>05 Oct 2026</td><td>69.9</td><td>(74.5)</td><td>0.0</td><td>(89.8)</td></tr>
    <tr><td>06 Oct 2026</td><td>-</td><td>-</td><td>-</td><td>0.0</td></tr>
    <tr><td>Total</td><td>65,802</td><td>10,831</td><td>(27,896)</td><td>57,767</td></tr>
  </tbody>
</table>`;

const FARSIDE_MARKDOWN_FIXTURE = `
Title: Farside Investors
URL Source: https://farside.co.uk/bitcoin-etf-flow-all-data/

| Date | IBIT | FBTC | GBTC | Total |
| --- | --- | --- | --- | --- |
| 01 Oct 2026 | 195\\.6 | (60\\.7) | (31\\.4) | 102\\.7 |
| 02 Oct 2026 | 158\\.2 | 29\\.3 | 0\\.0 | 189\\.9 |
| 05 Oct 2026 | 69\\.9 | (74\\.5) | 0\\.0 | (89\\.8) |
| 06 Oct 2026 | \\- | \\- | \\- | 0\\.0 |
`;

let server;
let baseUrl;
const nativeFetch = globalThis.fetch;

before(async () => {
  server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

test('parser reads Farside totals, accounting negatives, and ignores unreported rows', () => {
  const sessions = parseFarsideSessions(FARSIDE_FIXTURE);
  assert.equal(sessions.length, 6);
  assert.deepEqual(sessions[0], { date: '2026-09-28', netFlowUsdM: 31.0 });
  assert.deepEqual(sessions.at(-1), { date: '2026-10-05', netFlowUsdM: -89.8 });
});

test('parser reads escaped Markdown tables returned by the page reader', () => {
  const sessions = parseFarsideSessions(FARSIDE_MARKDOWN_FIXTURE);
  assert.equal(sessions.length, 3);
  assert.deepEqual(sessions[0], { date: '2026-10-01', netFlowUsdM: 102.7 });
  assert.deepEqual(sessions.at(-1), { date: '2026-10-05', netFlowUsdM: -89.8 });
});

test('signal logic requires net-flow sign and matching session breadth', () => {
  assert.equal(calculateFlowSignal(12.3, 4, 1), 'GREEN');
  assert.equal(calculateFlowSignal(-12.3, 1, 4), 'RED');
  assert.equal(calculateFlowSignal(12.3, 2, 3), 'YELLOW');
  assert.equal(calculateFlowSignal(-12.3, 3, 2), 'YELLOW');
  assert.equal(calculateFlowSignal(0, 2, 2), 'YELLOW');
});

test('summary uses the five latest reported sessions and excludes zero-flow holidays/unreported rows', () => {
  const result = summarizeEtfFlows(parseFarsideSessions(FARSIDE_FIXTURE), '2026-10-06T22:00:00.000Z');
  assert.equal(result.asOfDate, '2026-10-05');
  assert.equal(result.dailyNetFlowUsdM, -89.8);
  assert.equal(result.fiveSessionNetFlowUsdM, 120.3);
  assert.equal(result.positiveSessions, 3);
  assert.equal(result.negativeSessions, 2);
  assert.equal(result.signal, 'GREEN');
  assert.equal(result.sessions.length, 5);
  assert.equal(result.sessions[0].date, '2026-09-29');
  assert.equal(result.sessions.at(-1).date, '2026-10-05');
  assert.equal(result.sourceUrl, FARSIDE_BTC_ALL_DATA_URL);
});

test('summary refuses to fabricate a five-session value from incomplete data', () => {
  assert.throws(() => summarizeEtfFlows([{ date: '2026-10-05', netFlowUsdM: 1 }]), /at least 5 reported ETF sessions/);
});

test('GET /v1/btc/market/etf-flow returns live-shaped Farside summary data', async () => {
  globalThis.fetch = async (url, options) => {
    assert.equal(url, FARSIDE_FETCH_URL);
    assert.equal(options.method, 'GET');
    assert.equal(options.headers.Accept, 'text/plain');
    return new Response(FARSIDE_FIXTURE, { status: 200, headers: { 'Content-Type': 'text/html' } });
  };

  try {
    const response = await nativeFetch(`${baseUrl}/v1/btc/market/etf-flow`, {
      headers: { Origin: 'https://floreskain4-web.github.io' },
    });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('access-control-allow-origin'), 'https://floreskain4-web.github.io');
    assert.match(response.headers.get('cache-control'), /max-age=60/);
    const body = await response.json();
    assert.equal(body.source, 'Farside Investors');
    assert.equal(body.sourceUrl, FARSIDE_BTC_ALL_DATA_URL);
    assert.equal(body.retrievedVia, 'Jina Reader');
    assert.equal(body.dailyNetFlowUsdM, -89.8);
    assert.equal(body.fiveSessionNetFlowUsdM, 120.3);
    assert.equal(body.positiveSessions, 3);
    assert.equal(body.negativeSessions, 2);
    assert.equal(body.signal, 'GREEN');
  } finally {
    globalThis.fetch = nativeFetch;
  }
});

test('ETF flow endpoint is GET-only', async () => {
  const response = await nativeFetch(`${baseUrl}/v1/btc/market/etf-flow`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  });
  assert.equal(response.status, 404);
});

test('upstream failures return 502 without exposing upstream details', async () => {
  globalThis.fetch = async () => new Response('sensitive proxy response', { status: 403 });
  try {
    const response = await nativeFetch(`${baseUrl}/v1/btc/market/etf-flow`);
    assert.equal(response.status, 502);
    assert.deepEqual(await response.json(), { error: 'Farside ETF flow data is temporarily unavailable' });
  } finally {
    globalThis.fetch = nativeFetch;
  }
});
