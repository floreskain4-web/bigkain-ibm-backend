import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Psbt, payments } from 'bitcoinjs-lib';
import bitcoreMessage from 'bitcoinjs-message';
import * as ecc from 'tiny-secp256k1';

import app from '../server.js';
import * as signer from '../signer.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let server;
let base;

// --- throwaway keypair (generated fresh every run; never a real key) --------
const priv = randomBytes(32);
const pub = Buffer.from(ecc.pointFromScalar(priv, true));
const P2PKH_ADDR = payments.p2pkh({ pubkey: pub }).address;
const P2WPKH_ADDR = payments.p2wpkh({ pubkey: pub }).address;
const P2WPKH_SCRIPT_HEX = payments.p2wpkh({ pubkey: pub }).output.toString('hex');
const FAKE_TXID = 'aa'.repeat(32);
const FAKE_UTXO_VALUE = 100000;

function mempoolStub(url) {
  const u = String(url);
  const json = (data) => ({ ok: true, status: 200, json: async () => data, text: async () => JSON.stringify(data) });
  if (u.includes(`/address/${P2WPKH_ADDR}/utxo`)) {
    return json([{ txid: FAKE_TXID, vout: 0, value: FAKE_UTXO_VALUE, status: { confirmed: true } }]);
  }
  if (u.includes(`/tx/${FAKE_TXID}`) && !u.endsWith('/hex')) {
    return json({ vout: [{ scriptpubkey: P2WPKH_SCRIPT_HEX, scriptpubkey_address: P2WPKH_ADDR, value: FAKE_UTXO_VALUE }] });
  }
  return { ok: false, status: 404, json: async () => ({}), text: async () => '' };
}

const realFetch = globalThis.fetch;

async function post(p, body) {
  const res = await fetch(`${base}${p}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

before(async () => {
  globalThis.fetch = async (url, opts) => {
    if (String(url).startsWith('https://mempool.space/api/')) return mempoolStub(url);
    return realFetch(url, opts);
  };
  await new Promise((resolve) => { server = app.listen(0, resolve); });
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  globalThis.fetch = realFetch;
  try { fs.unlinkSync(path.join(__dirname, '..', 'receipts.jsonl')); } catch {}
  await new Promise((resolve) => server.close(resolve));
});

describe('POST /v1/signer/session', () => {
  test('creates a pending session', async () => {
    const { status, body } = await post('/v1/signer/session', { walletAddress: P2PKH_ADDR, purpose: 'SIGN_PSBT' });
    assert.equal(status, 200);
    assert.match(body.sessionId, /^bk_sess_[0-9a-f]{32}$/);
    assert.equal(body.walletAddress, P2PKH_ADDR);
    assert.equal(body.status, 'PENDING_APPROVAL');
    assert.ok(Date.parse(body.expiresAt) > Date.now());
  });

  test('invalid address -> 400', async () => {
    const { status } = await post('/v1/signer/session', { walletAddress: 'nope', purpose: 'x' });
    assert.equal(status, 400);
  });

  test('missing purpose -> 400', async () => {
    const { status } = await post('/v1/signer/session', { walletAddress: P2PKH_ADDR });
    assert.equal(status, 400);
  });

  test('key-like field rejected by guard', async () => {
    const { status, body } = await post('/v1/signer/session', {
      walletAddress: P2PKH_ADDR, purpose: 'x', privateKey: 'K' + 'x'.repeat(51),
    });
    assert.equal(status, 400);
    assert.match(body.error, /private keys/i);
  });
});

describe('POST /v1/signer/challenge', () => {
  test('issues a challenge for a live session', async () => {
    const s = await post('/v1/signer/session', { walletAddress: P2PKH_ADDR, purpose: 'SIGN_PSBT' });
    const { status, body } = await post('/v1/signer/challenge', { sessionId: s.body.sessionId });
    assert.equal(status, 200);
    assert.match(body.challengeId, /^bk_ch_[0-9a-f]{32}$/);
    assert.match(body.nonce, /^BK-/);
    assert.equal(body.walletAddress, P2PKH_ADDR);
    assert.ok(!('used' in body));
  });

  test('unknown session -> 404', async () => {
    const { status } = await post('/v1/signer/challenge', { sessionId: 'bk_sess_' + '0'.repeat(32) });
    assert.equal(status, 404);
  });

  test('expired session -> 404', async () => {
    const s = await post('/v1/signer/session', { walletAddress: P2PKH_ADDR, purpose: 'x' });
    signer._stores.sessions.get(s.body.sessionId).expiresAt = new Date(Date.now() - 1000).toISOString();
    const { status } = await post('/v1/signer/challenge', { sessionId: s.body.sessionId });
    assert.equal(status, 404);
  });
});

describe('ownership challenge + verify (replay protection)', () => {
  test('full flow: challenge -> sign -> verify true, replay rejected', async () => {
    const c = await post('/v1/btc/ownership/challenge', { address: P2PKH_ADDR });
    assert.equal(c.status, 200);
    assert.match(c.body.challengeId, /^bk_ch_/);
    assert.match(c.body.message, /BIGKAIN OWNERSHIP PROOF/);

    const sig = bitcoreMessage.sign(c.body.message, priv, true).toString('base64');
    const v1 = await post('/v1/btc/ownership/verify', {
      address: P2PKH_ADDR, message: c.body.message, signature: sig, challengeId: c.body.challengeId,
    });
    assert.equal(v1.body.valid, true);

    const v2 = await post('/v1/btc/ownership/verify', {
      address: P2PKH_ADDR, message: c.body.message, signature: sig, challengeId: c.body.challengeId,
    });
    assert.equal(v2.body.valid, false);
    assert.match(v2.body.reason, /replay/i);
  });

  test('challenge bound to message: wrong message rejected', async () => {
    const c = await post('/v1/btc/ownership/challenge', { address: P2PKH_ADDR });
    const sig = bitcoreMessage.sign('something else', priv, true).toString('base64');
    const v = await post('/v1/btc/ownership/verify', {
      address: P2PKH_ADDR, message: 'something else', signature: sig, challengeId: c.body.challengeId,
    });
    assert.equal(v.body.valid, false);
    assert.match(v.body.reason, /does not match/);
  });

  test('verify without challengeId still works (legacy path)', async () => {
    const message = 'plain verify ' + Date.now();
    const sig = bitcoreMessage.sign(message, priv, true).toString('base64');
    const v = await post('/v1/btc/ownership/verify', { address: P2PKH_ADDR, message, signature: sig });
    assert.equal(v.body.valid, true);
  });

  test('tampered signature -> valid false', async () => {
    const sig = bitcoreMessage.sign('abc', priv, true).toString('base64');
    const v = await post('/v1/btc/ownership/verify', { address: P2PKH_ADDR, message: 'xyz', signature: sig });
    assert.equal(v.body.valid, false);
  });

  test('unknown challengeId -> 400', async () => {
    const v = await post('/v1/btc/ownership/verify', {
      address: P2PKH_ADDR, message: 'm', signature: 'c2ln', challengeId: 'bk_ch_' + 'f'.repeat(32),
    });
    assert.equal(v.status, 400);
  });
});

describe('POST /v1/btc/psbt/prepare', () => {
  test('builds an unsigned PSBT with sane shape', async () => {
    const destPriv = randomBytes(32);
    const dest = payments.p2wpkh({ pubkey: Buffer.from(ecc.pointFromScalar(destPriv, true)) }).address;
    const { status, body } = await post('/v1/btc/psbt/prepare', {
      walletAddress: P2WPKH_ADDR, destination: dest, amountSats: 50000, feeRateSatVb: 5,
    });
    assert.equal(status, 200);
    assert.ok(typeof body.psbt === 'string' && body.psbt.length > 50);
    assert.equal(body.inputs.length, 1);
    assert.equal(body.inputs[0].txid, FAKE_TXID);
    assert.equal(body.outputs[0].address, dest);
    assert.equal(body.outputs[0].sats, 50000);
    assert.ok(body.outputs[1].change === true);
    assert.ok(body.feeSats > 0);
    // round-trip decode: unsigned, one input, two outputs
    const psbt = Psbt.fromBase64(body.psbt);
    assert.equal(psbt.inputCount, 1);
    assert.equal(psbt.txOutputs.length, 2);
    assert.equal((psbt.data.inputs[0].partialSig || []).length, 0);
  });

  test('invalid destination -> 400', async () => {
    const { status } = await post('/v1/btc/psbt/prepare', {
      walletAddress: P2WPKH_ADDR, destination: 'bad', amountSats: 100, feeRateSatVb: 5,
    });
    assert.equal(status, 400);
  });

  test('insufficient funds -> 400', async () => {
    const dest = payments.p2wpkh({ pubkey: Buffer.from(ecc.pointFromScalar(randomBytes(32), true)) }).address;
    const { status, body } = await post('/v1/btc/psbt/prepare', {
      walletAddress: P2WPKH_ADDR, destination: dest, amountSats: 99999999, feeRateSatVb: 5,
    });
    assert.equal(status, 400);
    assert.match(body.error, /insufficient/);
  });

  test('fee rate out of bounds -> 400', async () => {
    const dest = payments.p2wpkh({ pubkey: Buffer.from(ecc.pointFromScalar(randomBytes(32), true)) }).address;
    const { status } = await post('/v1/btc/psbt/prepare', {
      walletAddress: P2WPKH_ADDR, destination: dest, amountSats: 100, feeRateSatVb: 5000,
    });
    assert.equal(status, 400);
  });
});

describe('POST /v1/btc/psbt/validate', () => {
  function signedPsbtFixture() {
    const dest = payments.p2wpkh({ pubkey: Buffer.from(ecc.pointFromScalar(randomBytes(32), true)) }).address;
    const psbt = new Psbt();
    psbt.setVersion(2);
    psbt.addInput({
      hash: Buffer.from(FAKE_TXID, 'hex').reverse(),
      index: 0,
      sequence: 0xfffffffd,
      witnessUtxo: { script: Buffer.from(P2WPKH_SCRIPT_HEX, 'hex'), value: FAKE_UTXO_VALUE },
    });
    psbt.addOutput({ address: dest, value: 50000 });
    psbt.addOutput({ address: P2WPKH_ADDR, value: 49000 });
    psbt.signInput(0, { publicKey: pub, sign: (h) => Buffer.from(ecc.sign(h, priv)) });
    return { psbt: psbt.toBase64(), dest, wallet: P2WPKH_ADDR };
  }

  test('signed PSBT matching expectations -> SAFE_HOLD', async () => {
    const f = signedPsbtFixture();
    const { status, body } = await post('/v1/btc/psbt/validate', {
      psbt: f.psbt,
      expected: { destination: f.dest, amountSats: 50000, walletAddress: f.wallet, feeRateSatVb: 10 },
    });
    assert.equal(status, 200);
    assert.equal(body.valid, true);
    assert.equal(body.verdict, 'SAFE_HOLD');
    assert.deepEqual(body.reasons, []);
  });

  test('wrong destination -> REJECT', async () => {
    const f = signedPsbtFixture();
    const other = payments.p2wpkh({ pubkey: Buffer.from(ecc.pointFromScalar(randomBytes(32), true)) }).address;
    const { body } = await post('/v1/btc/psbt/validate', {
      psbt: f.psbt,
      expected: { destination: other, amountSats: 50000, walletAddress: f.wallet },
    });
    assert.equal(body.valid, false);
    assert.equal(body.verdict, 'REJECT');
    assert.ok(body.reasons.some((r) => /destination/.test(r)));
  });

  test('wrong amount -> REJECT', async () => {
    const f = signedPsbtFixture();
    const { body } = await post('/v1/btc/psbt/validate', {
      psbt: f.psbt,
      expected: { destination: f.dest, amountSats: 49999, walletAddress: f.wallet },
    });
    assert.equal(body.valid, false);
    assert.equal(body.verdict, 'REJECT');
  });

  test('unsigned PSBT -> REJECT (unsigned inputs)', async () => {
    const dest = payments.p2wpkh({ pubkey: Buffer.from(ecc.pointFromScalar(randomBytes(32), true)) }).address;
    const psbt = new Psbt();
    psbt.addInput({
      hash: Buffer.from(FAKE_TXID, 'hex').reverse(), index: 0,
      witnessUtxo: { script: Buffer.from(P2WPKH_SCRIPT_HEX, 'hex'), value: FAKE_UTXO_VALUE },
    });
    psbt.addOutput({ address: dest, value: 50000 });
    const { body } = await post('/v1/btc/psbt/validate', {
      psbt: psbt.toBase64(),
      expected: { destination: dest, amountSats: 50000, walletAddress: P2WPKH_ADDR },
    });
    assert.equal(body.valid, false);
    assert.ok(body.reasons.some((r) => /unsigned inputs/.test(r)));
  });

  test('input not belonging to wallet -> REJECT', async () => {
    const f = signedPsbtFixture();
    const other = payments.p2pkh({ pubkey: Buffer.from(ecc.pointFromScalar(randomBytes(32), true)) }).address;
    const { body } = await post('/v1/btc/psbt/validate', {
      psbt: f.psbt,
      expected: { destination: f.dest, amountSats: 50000, walletAddress: other },
    });
    assert.equal(body.valid, false);
    assert.ok(body.reasons.some((r) => /not wallet/.test(r)));
  });

  test('garbage psbt -> REJECT', async () => {
    const { body } = await post('/v1/btc/psbt/validate', {
      psbt: 'not-base64!!',
      expected: { destination: P2WPKH_ADDR, amountSats: 1, walletAddress: P2WPKH_ADDR },
    });
    assert.equal(body.valid, false);
    assert.equal(body.verdict, 'REJECT');
  });
});

describe('POST /v1/btc/receipt', () => {
  test('records a receipt', async () => {
    const txid = 'bb'.repeat(32);
    const { status, body } = await post('/v1/btc/receipt', { txid, note: 'test receipt', amountSats: 50000 });
    assert.equal(status, 200);
    assert.equal(body.recorded, true);
    assert.equal(body.txid, txid);
    assert.equal(signer._stores.receipts.length, 1);
  });

  test('bad txid -> 400', async () => {
    const { status } = await post('/v1/btc/receipt', { txid: 'xyz' });
    assert.equal(status, 400);
  });
});
