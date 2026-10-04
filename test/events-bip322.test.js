import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import app from '../server.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let server;
let base;

async function post(p, body) {
  const res = await fetch(`${base}${p}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

async function get(p) {
  const res = await fetch(`${base}${p}`);
  return { status: res.status, body: await res.json() };
}

before(async () => {
  await new Promise((resolve) => { server = app.listen(0, resolve); });
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  server.close();
  try { fs.unlinkSync(path.join(__dirname, '..', 'receipts.jsonl')); } catch { /* ignore */ }
});

// ---------------------------------------------------------------------------
// Official BIP-322 test vectors (bip-0322.mediawiki, "Test vectors").
// Private key L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k is the
// SPEC's burned test key — never a real key.
// ---------------------------------------------------------------------------
const VEC_ADDR = 'bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l';
const VEC_MSG = 'Hello World';
const VEC_SIMPLE_SIG = 'AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=';
const VEC_FULL_SIG = 'AkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy';
const VEC_EMPTY_SIG = 'AkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=';
const WRONG_ADDR = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'; // BIP-173 example address

describe('POST /v1/btc/bip322/verify (official BIP-322 vectors)', () => {
  test('valid simple signature verifies true', async () => {
    const r = await post('/v1/btc/bip322/verify', { address: VEC_ADDR, message: VEC_MSG, signature: VEC_SIMPLE_SIG });
    assert.equal(r.status, 200);
    assert.equal(r.body.valid, true);
    assert.equal(r.body.address, VEC_ADDR);
    assert.equal(r.body.scheme, 'bip322');
  });

  test('valid full (transaction) signature verifies true', async () => {
    const r = await post('/v1/btc/bip322/verify', { address: VEC_ADDR, message: VEC_MSG, signature: VEC_FULL_SIG });
    assert.equal(r.status, 200);
    assert.equal(r.body.valid, true);
  });

  test('empty-message vector verifies true', async () => {
    const r = await post('/v1/btc/bip322/verify', { address: VEC_ADDR, message: '', signature: VEC_EMPTY_SIG });
    assert.equal(r.status, 200);
    assert.equal(r.body.valid, true);
  });

  test('tampered message verifies false', async () => {
    const r = await post('/v1/btc/bip322/verify', { address: VEC_ADDR, message: 'Hello World!', signature: VEC_SIMPLE_SIG });
    assert.equal(r.status, 200);
    assert.equal(r.body.valid, false);
  });

  test('tampered signature verifies false', async () => {
    const bad = VEC_SIMPLE_SIG.slice(0, 30) + (VEC_SIMPLE_SIG[30] === 'A' ? 'B' : 'A') + VEC_SIMPLE_SIG.slice(31);
    const r = await post('/v1/btc/bip322/verify', { address: VEC_ADDR, message: VEC_MSG, signature: bad });
    assert.equal(r.status, 200);
    assert.equal(r.body.valid, false);
  });

  test('wrong address verifies false', async () => {
    const r = await post('/v1/btc/bip322/verify', { address: WRONG_ADDR, message: VEC_MSG, signature: VEC_SIMPLE_SIG });
    assert.equal(r.status, 200);
    assert.equal(r.body.valid, false);
  });

  test('garbage signature returns valid:false, not a 500', async () => {
    const r = await post('/v1/btc/bip322/verify', { address: VEC_ADDR, message: VEC_MSG, signature: 'not-a-signature!!!' });
    assert.equal(r.status, 200);
    assert.equal(r.body.valid, false);
  });

  test('P2PKH address is routed to the legacy endpoint', async () => {
    const r = await post('/v1/btc/bip322/verify', { address: '1Ay8vMC7R1UbyCCZRVULMV7iQpHSAbguJP', message: VEC_MSG, signature: VEC_SIMPLE_SIG });
    assert.equal(r.status, 200);
    assert.equal(r.body.valid, false);
    assert.match(r.body.reason, /legacy/);
  });

  test('missing fields -> 400', async () => {
    const r = await post('/v1/btc/bip322/verify', { address: VEC_ADDR, message: VEC_MSG });
    assert.equal(r.status, 400);
    assert.equal(r.body.valid, false);
  });

  test('key guard rejects key-like fields', async () => {
    const r = await post('/v1/btc/bip322/verify', { address: VEC_ADDR, message: VEC_MSG, signature: VEC_SIMPLE_SIG, privateKey: 'x' });
    assert.equal(r.status, 400);
    assert.match(r.body.error, /never accepts/);
  });
});

describe('GET /events audit log', () => {
  test('endpoint activity is logged and readable', async () => {
    const s = await post('/v1/signer/session', { walletAddress: VEC_ADDR, purpose: 'audit-test' });
    assert.equal(s.status, 200);
    await post('/v1/signer/challenge', { sessionId: s.body.sessionId });

    const r = await get('/events');
    assert.equal(r.status, 200);
    assert.ok(r.body.count >= 1);
    const ch = r.body.events.find((e) => e.type === 'signer.challenge');
    assert.ok(ch, 'signer.challenge event present');
    assert.ok(ch.ts && ch.type);
    // session id must be truncated, never logged whole
    assert.ok(!JSON.stringify(ch.detail).includes(s.body.sessionId));
  });

  test('ownership.verify logs address + verdict, never the message or signature', async () => {
    const msg = 'audit-secret-message-xyz';
    const sig = 'audit-sig-abc';
    await post('/v1/btc/ownership/verify', { address: VEC_ADDR, message: msg, signature: sig });
    const r = await get('/events?limit=200');
    const ev = r.body.events.find((e) => e.type === 'ownership.verify');
    assert.ok(ev);
    assert.equal(ev.detail.valid, false);
    const blob = JSON.stringify(r.body.events);
    assert.ok(!blob.includes(msg), 'message text must not appear in the audit log');
    assert.ok(!blob.includes(sig), 'signature must not appear in the audit log');
  });

  test('receipt and bip322.verify are logged', async () => {
    const txid = 'bb'.repeat(32);
    await post('/v1/btc/receipt', { txid });
    await post('/v1/btc/bip322/verify', { address: VEC_ADDR, message: VEC_MSG, signature: VEC_SIMPLE_SIG });
    const r = await get('/events?limit=200');
    const rc = r.body.events.find((e) => e.type === 'receipt');
    assert.ok(rc && rc.detail.txid === txid);
    const b = r.body.events.find((e) => e.type === 'bip322.verify');
    assert.ok(b && b.detail.valid === true && b.detail.address === VEC_ADDR);
  });

  test('limit param is honored and capped', async () => {
    const one = await get('/events?limit=1');
    assert.equal(one.body.count, 1);
    assert.equal(one.body.events.length, 1);
    const capped = await get('/events?limit=99999');
    assert.ok(capped.body.count <= 200);
  });

  test('newest events come first', async () => {
    const r = await get('/events?limit=50');
    const ts = r.body.events.map((e) => e.ts);
    const sorted = [...ts].sort().reverse();
    assert.deepEqual(ts, sorted);
  });
});
