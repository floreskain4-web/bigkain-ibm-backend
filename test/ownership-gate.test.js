import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { payments } from 'bitcoinjs-lib';
import bitcoreMessage from 'bitcoinjs-message';
import * as ecc from 'tiny-secp256k1';
import { Signer as Bip322Signer } from 'bip322-js';

import app from '../server.js';
import * as signer from '../signer.js';

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

before(async () => {
  await new Promise((resolve) => { server = app.listen(0, resolve); });
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

// --- throwaway P2PKH keypair (fresh every run; never a real key) ------------
const priv = randomBytes(32);
const pub = Buffer.from(ecc.pointFromScalar(priv, true));
const P2PKH_ADDR = payments.p2pkh({ pubkey: pub }).address;

// --- BIP-322 spec's burned test key (published in the BIP; never real) ------
const SPEC_WIF = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
const SPEC_ADDR = 'bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l';

describe('ownership gate: challenge issuance', () => {
  test('issues a well-formed challenge', async () => {
    const { status, body } = await post('/v1/btc/ownership/challenge', { address: P2PKH_ADDR });
    assert.equal(status, 200);
    assert.match(body.challengeId, /^bk_ch_[0-9a-f]{32}$/);
    assert.equal(body.address, P2PKH_ADDR);
    assert.match(body.message, /BIGKAIN OWNERSHIP PROOF/);
    assert.match(body.message, new RegExp(P2PKH_ADDR));
    assert.match(body.message, /Nonce: [0-9a-f]{32}/);
    assert.ok(Date.parse(body.expiresAt) > Date.now());
    // the stored record carries the nonce for check 3
    const rec = signer._stores.ownershipChallenges.get(body.challengeId);
    assert.ok(rec && typeof rec.nonce === 'string' && body.message.includes(rec.nonce));
  });

  test('invalid address -> 400', async () => {
    const { status } = await post('/v1/btc/ownership/challenge', { address: 'nope' });
    assert.equal(status, 400);
  });

  test('each challenge gets a fresh nonce', async () => {
    const a = await post('/v1/btc/ownership/challenge', { address: P2PKH_ADDR });
    const b = await post('/v1/btc/ownership/challenge', { address: P2PKH_ADDR });
    assert.notEqual(a.body.challengeId, b.body.challengeId);
    assert.notEqual(a.body.message, b.body.message);
  });
});

describe('ownership gate: legacy P2PKH path (all six checks)', () => {
  test('GREEN: challenge -> sign exact message -> verify true', async () => {
    const c = await post('/v1/btc/ownership/challenge', { address: P2PKH_ADDR });
    const sig = bitcoreMessage.sign(c.body.message, priv, true).toString('base64');
    const v = await post('/v1/btc/ownership/verify', {
      address: P2PKH_ADDR, message: c.body.message, signature: sig, challengeId: c.body.challengeId,
    });
    assert.equal(v.status, 200);
    assert.equal(v.body.valid, true);
    assert.equal(v.body.gated, true);
    assert.equal(v.body.scheme, 'legacy');
  });

  test('check 1: wrong address rejected', async () => {
    const other = payments.p2pkh({ pubkey: Buffer.from(ecc.pointFromScalar(randomBytes(32), true)) }).address;
    const c = await post('/v1/btc/ownership/challenge', { address: P2PKH_ADDR });
    const sig = bitcoreMessage.sign(c.body.message, priv, true).toString('base64');
    const v = await post('/v1/btc/ownership/verify', {
      address: other, message: c.body.message, signature: sig, challengeId: c.body.challengeId,
    });
    assert.equal(v.body.valid, false);
    assert.match(v.body.reason, /address does not match/i);
  });

  test('check 2: tampered message rejected', async () => {
    const c = await post('/v1/btc/ownership/challenge', { address: P2PKH_ADDR });
    const sig = bitcoreMessage.sign(c.body.message, priv, true).toString('base64');
    const v = await post('/v1/btc/ownership/verify', {
      address: P2PKH_ADDR, message: c.body.message + ' ', signature: sig, challengeId: c.body.challengeId,
    });
    assert.equal(v.body.valid, false);
    assert.match(v.body.reason, /message does not match/i);
  });

  test('check 3: swapped nonce rejected', async () => {
    const c = await post('/v1/btc/ownership/challenge', { address: P2PKH_ADDR });
    const tampered = c.body.message.replace(/Nonce: [0-9a-f]{32}/, 'Nonce: ' + '0'.repeat(32));
    assert.notEqual(tampered, c.body.message);
    const sig = bitcoreMessage.sign(tampered, priv, true).toString('base64');
    const v = await post('/v1/btc/ownership/verify', {
      address: P2PKH_ADDR, message: tampered, signature: sig, challengeId: c.body.challengeId,
    });
    assert.equal(v.body.valid, false);
    assert.match(v.body.reason, /message does not match/i);
  });

  test('check 4: expired challenge rejected with 400', async () => {
    const c = await post('/v1/btc/ownership/challenge', { address: P2PKH_ADDR });
    signer._stores.ownershipChallenges.get(c.body.challengeId).expiresAt =
      new Date(Date.now() - 1000).toISOString();
    const v = await post('/v1/btc/ownership/verify', {
      address: P2PKH_ADDR, message: c.body.message, signature: 'c2ln', challengeId: c.body.challengeId,
    });
    assert.equal(v.status, 400);
    assert.match(v.body.reason, /expired/i);
  });

  test('check 5: replay rejected — challenge is single-use', async () => {
    const c = await post('/v1/btc/ownership/challenge', { address: P2PKH_ADDR });
    const sig = bitcoreMessage.sign(c.body.message, priv, true).toString('base64');
    const v1 = await post('/v1/btc/ownership/verify', {
      address: P2PKH_ADDR, message: c.body.message, signature: sig, challengeId: c.body.challengeId,
    });
    assert.equal(v1.body.valid, true);
    const v2 = await post('/v1/btc/ownership/verify', {
      address: P2PKH_ADDR, message: c.body.message, signature: sig, challengeId: c.body.challengeId,
    });
    assert.equal(v2.body.valid, false);
    assert.match(v2.body.reason, /already used/i);
  });

  test('check 5b: binding failure does not burn; one signature attempt after binding passes', async () => {
    const c = await post('/v1/btc/ownership/challenge', { address: P2PKH_ADDR });
    const badSig = bitcoreMessage.sign('wrong message', priv, true).toString('base64');
    const v1 = await post('/v1/btc/ownership/verify', {
      address: P2PKH_ADDR, message: 'wrong message', signature: badSig, challengeId: c.body.challengeId,
    });
    assert.equal(v1.body.valid, false);
    // binding failure did NOT burn the challenge: the real attempt still works
    const goodSig = bitcoreMessage.sign(c.body.message, priv, true).toString('base64');
    const v2 = await post('/v1/btc/ownership/verify', {
      address: P2PKH_ADDR, message: c.body.message, signature: goodSig, challengeId: c.body.challengeId,
    });
    assert.equal(v2.body.valid, true);
    // but now it IS burned: replay rejected
    const v3 = await post('/v1/btc/ownership/verify', {
      address: P2PKH_ADDR, message: c.body.message, signature: goodSig, challengeId: c.body.challengeId,
    });
    assert.equal(v3.body.valid, false);
    assert.match(v3.body.reason, /already used/i);
  });

  test('check 6: bad signature -> valid false', async () => {
    const c = await post('/v1/btc/ownership/challenge', { address: P2PKH_ADDR });
    const sig = bitcoreMessage.sign('something else entirely', priv, true).toString('base64');
    const v = await post('/v1/btc/ownership/verify', {
      address: P2PKH_ADDR, message: c.body.message, signature: sig, challengeId: c.body.challengeId,
    });
    assert.equal(v.body.valid, false);
    assert.equal(v.body.gated, true);
  });

  test('bare verify without challengeId still works, marked gated:false', async () => {
    const message = 'plain verify ' + Date.now();
    const sig = bitcoreMessage.sign(message, priv, true).toString('base64');
    const v = await post('/v1/btc/ownership/verify', { address: P2PKH_ADDR, message, signature: sig });
    assert.equal(v.body.valid, true);
    assert.equal(v.body.gated, false);
    assert.equal(v.body.scheme, 'legacy');
  });
});

describe('ownership gate: BIP-322 segwit path (all six checks)', () => {
  test('GREEN: challenge -> BIP-322 sign -> verify true', async () => {
    const c = await post('/v1/btc/ownership/challenge', { address: SPEC_ADDR });
    assert.equal(c.status, 200);
    const sig = Bip322Signer.sign(SPEC_WIF, SPEC_ADDR, c.body.message);
    const v = await post('/v1/btc/ownership/verify', {
      address: SPEC_ADDR, message: c.body.message, signature: sig, challengeId: c.body.challengeId,
    });
    assert.equal(v.status, 200);
    assert.equal(v.body.valid, true);
    assert.equal(v.body.gated, true);
    assert.equal(v.body.scheme, 'bip322');
  });

  test('segwit replay rejected', async () => {
    const c = await post('/v1/btc/ownership/challenge', { address: SPEC_ADDR });
    const sig = Bip322Signer.sign(SPEC_WIF, SPEC_ADDR, c.body.message);
    const v1 = await post('/v1/btc/ownership/verify', {
      address: SPEC_ADDR, message: c.body.message, signature: sig, challengeId: c.body.challengeId,
    });
    assert.equal(v1.body.valid, true);
    const v2 = await post('/v1/btc/ownership/verify', {
      address: SPEC_ADDR, message: c.body.message, signature: sig, challengeId: c.body.challengeId,
    });
    assert.equal(v2.body.valid, false);
    assert.match(v2.body.reason, /already used/i);
  });

  test('segwit wrong message rejected', async () => {
    const c = await post('/v1/btc/ownership/challenge', { address: SPEC_ADDR });
    const sig = Bip322Signer.sign(SPEC_WIF, SPEC_ADDR, 'different message');
    const v = await post('/v1/btc/ownership/verify', {
      address: SPEC_ADDR, message: c.body.message, signature: sig, challengeId: c.body.challengeId,
    });
    assert.equal(v.body.valid, false);
  });

  test('segwit signature for the wrong address rejected', async () => {
    const c = await post('/v1/btc/ownership/challenge', { address: SPEC_ADDR });
    // sign the right message but the gate binds the challenge to SPEC_ADDR;
    // submitting under a different address fails check 1 first
    const other = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
    const sig = Bip322Signer.sign(SPEC_WIF, SPEC_ADDR, c.body.message);
    const v = await post('/v1/btc/ownership/verify', {
      address: other, message: c.body.message, signature: sig, challengeId: c.body.challengeId,
    });
    assert.equal(v.body.valid, false);
    assert.match(v.body.reason, /address does not match/i);
  });

  test('segwit tampered signature -> valid false', async () => {
    const c = await post('/v1/btc/ownership/challenge', { address: SPEC_ADDR });
    const sig = Bip322Signer.sign(SPEC_WIF, SPEC_ADDR, c.body.message);
    const bad = sig.slice(0, -4) + 'AAAA';
    const v = await post('/v1/btc/ownership/verify', {
      address: SPEC_ADDR, message: c.body.message, signature: bad, challengeId: c.body.challengeId,
    });
    assert.equal(v.body.valid, false);
    assert.equal(v.body.gated, true);
  });
});

describe('ownership gate: key-material guard', () => {
  test('challenge endpoint rejects key-like fields', async () => {
    const { status, body } = await post('/v1/btc/ownership/challenge', {
      address: P2PKH_ADDR, privateKey: 'K' + 'x'.repeat(51),
    });
    assert.equal(status, 400);
    assert.match(body.error, /private keys/i);
  });
});
