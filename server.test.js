import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import bitcoreMessage from 'bitcoinjs-message';
import { payments } from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';
import { randomBytes } from 'node:crypto';

import app from '../server.js';

let server;
let base;

test('setup: start server on ephemeral port', async () => {
  await new Promise((resolve) => {
    server = app.listen(0, resolve);
  });
  base = `http://127.0.0.1:${server.address().port}`;
});

describe('GET /health', () => {
  test('returns ok with service metadata', async () => {
    const res = await fetch(`${base}/health`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.service, 'bigkain-backend');
    assert.equal(body.network, 'bitcoin-mainnet');
    assert.equal(body.ownership_address, '1Ay8vMC7R1UbyCCZRVULMV7iQpHSAbguJP');
    assert.equal(body.private_keys_received, false);
    assert.ok('ownership_proof' in body);
  });
});

describe('POST /verify', () => {
  test('missing fields -> 400', async () => {
    const res = await fetch(`${base}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa' }),
    });
    assert.equal(res.status, 400);
  });

  test('input too long -> 400', async () => {
    const res = await fetch(`${base}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', message: 'x'.repeat(9000), signature: 'y' }),
    });
    assert.equal(res.status, 400);
  });

  test('bad signature -> valid false', async () => {
    const res = await fetch(`${base}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', message: 'hello', signature: 'bm90YS1zaWduYXR1cmU=' }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.valid, false);
  });
});

describe('POST /verify-ownership', () => {
  test('valid P2PKH signature verifies true (throwaway key)', async () => {
    const priv = randomBytes(32);
    const pub = Buffer.from(ecc.pointFromScalar(priv, true));
    const address = payments.p2pkh({ pubkey: pub }).address;
    const message = 'bigkain test ' + Date.now();
    const signature = bitcoreMessage.sign(message, priv, true).toString('base64');

    const res = await fetch(`${base}/verify-ownership`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address, message, signature }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.valid, true);
    assert.equal(body.address, address);
  });

  test('tampered message verifies false', async () => {
    const priv = randomBytes(32);
    const pub = Buffer.from(ecc.pointFromScalar(priv, true));
    const address = payments.p2pkh({ pubkey: pub }).address;
    const signature = bitcoreMessage.sign('original', priv, true).toString('base64');

    const res = await fetch(`${base}/verify-ownership`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address, message: 'tampered', signature }),
    });
    const body = await res.json();
    assert.equal(body.valid, false);
  });

  test('missing fields -> 400', async () => {
    const res = await fetch(`${base}/verify-ownership`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa' }),
    });
    assert.equal(res.status, 400);
  });

  test('bech32 address -> valid false with reason', async () => {
    const res = await fetch(`${base}/verify-ownership`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        address: 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',
        message: 'x',
        signature: 'y',
      }),
    });
    const body = await res.json();
    assert.equal(body.valid, false);
    assert.match(body.reason, /BIP-322/);
  });
});

describe('address endpoints validate input', () => {
  test('GET /address/notanaddress -> 400', async () => {
    const res = await fetch(`${base}/address/notanaddress`);
    assert.equal(res.status, 400);
  });

  test('POST /attest without INSUMER_API_KEY -> 501', async () => {
    const res = await fetch(`${base}/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bitcoinWallet: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', conditions: [] }),
    });
    assert.equal(res.status, 501);
  });

  test('unknown route -> 404', async () => {
    const res = await fetch(`${base}/nope`);
    assert.equal(res.status, 404);
  });
});

test('teardown: stop server', async () => {
  await new Promise((resolve) => server.close(resolve));
});
