import { test, before, beforeEach, after, describe } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import express from 'express';
import { Psbt, Transaction, payments } from 'bitcoinjs-lib';
import bitcoreMessage from 'bitcoinjs-message';
import * as ecc from 'tiny-secp256k1';

import { createSignerRouter, _stores } from '../signer.js';
import { createMemoryTransactionStore } from '../transaction-store.js';

const priv = randomBytes(32);
const pub = Buffer.from(ecc.pointFromScalar(priv, true));
const walletAddress = payments.p2pkh({ pubkey: pub }).address;
const walletScript = payments.p2pkh({ pubkey: pub }).output;
const walletScriptHex = walletScript.toString('hex');
const DESTINATION = payments.p2pkh({ pubkey: Buffer.from(ecc.pointFromScalar(randomBytes(32), true)) }).address;
const prevouts = new Map();
const transactionStore = createMemoryTransactionStore();
let server;
let disabledServer;
let base;
let disabledBase;

function makeApp({ store = createMemoryTransactionStore() } = {}) {
  const app = express();
  app.use(express.json({ limit: '100kb' }));
  app.use(createSignerRouter({
    mempool: async (path) => {
      const hit = path.match(/^\/tx\/([0-9a-f]{64})$/i);
      const prevout = hit && prevouts.get(hit[1].toLowerCase());
      if (!prevout) throw Object.assign(new Error('missing test previous output'), { status: 404 });
      return {
        status: { confirmed: prevout.confirmed !== false },
        vout: [{ scriptpubkey: prevout.scriptHex, value: prevout.value }],
      };
    },
    transactionStore: store,
  }));
  app.use((_req, res) => res.status(404).json({ error: 'not found' }));
  return app;
}

function fixture(inputValue = 100000) {
  const prevTx = new Transaction();
  prevTx.addInput(Buffer.from(randomBytes(32)).reverse(), 1);
  prevTx.addOutput(walletScript, inputValue);
  const prevTxid = prevTx.getId().toLowerCase();
  prevouts.set(prevTxid, { scriptHex: walletScriptHex, value: inputValue, confirmed: true });

  const psbt = new Psbt();
  psbt.setVersion(2);
  psbt.addInput({
    hash: Buffer.from(prevTxid, 'hex').reverse(),
    index: 0,
    sequence: 0xfffffffd,
    nonWitnessUtxo: prevTx.toBuffer(),
  });
  psbt.addOutput({ address: DESTINATION, value: 50000 });
  psbt.addOutput({ address: walletAddress, value: inputValue - 51000 });
  return {
    psbtBase64: psbt.toBase64(),
    prevTxid,
    expected: { walletAddress, destination: DESTINATION, amountSats: 50000, feeRateSatVb: 5 },
  };
}

async function post(urlBase, route, body) {
  const response = await fetch(`${urlBase}${route}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

async function challengeFor(f) {
  return post(base, '/v1/btc/ownership/challenge', {
    address: f.expected.walletAddress,
    psbt: f.psbtBase64,
  });
}

function signedOwnershipProof(message) {
  return bitcoreMessage.sign(message, priv, true).toString('base64');
}

function approvalRequest(f, challenge, signature = signedOwnershipProof(challenge.body.message), psbtBase64 = f.psbtBase64) {
  return {
    psbt: psbtBase64,
    expected: f.expected,
    challengeId: challenge.body.challengeId,
    message: challenge.body.message,
    signature,
    explicitApproval: {
      approved: true,
      transactionCommitment: challenge.body.transactionCommitment,
      walletAddress: f.expected.walletAddress,
      destination: f.expected.destination,
      amountSats: f.expected.amountSats,
    },
  };
}

async function approve(f) {
  const challenge = await challengeFor(f);
  assert.equal(challenge.status, 200);
  const result = await post(base, '/v1/btc/transaction/approve', approvalRequest(f, challenge));
  return { challenge, result };
}

before(async () => {
  _stores.ownershipChallenges.clear();
  transactionStore.clear();
  server = makeApp({ store: transactionStore }).listen(0);
  disabledServer = makeApp({ store: null }).listen(0);
  await Promise.all([
    new Promise((resolve) => server.once('listening', resolve)),
    new Promise((resolve) => disabledServer.once('listening', resolve)),
  ]);
  base = `http://127.0.0.1:${server.address().port}`;
  disabledBase = `http://127.0.0.1:${disabledServer.address().port}`;
});

beforeEach(() => {
  _stores.ownershipChallenges.clear();
  transactionStore.clear();
  prevouts.clear();
});

after(async () => {
  await Promise.all([
    new Promise((resolve) => server.close(resolve)),
    new Promise((resolve) => disabledServer.close(resolve)),
  ]);
  _stores.ownershipChallenges.clear();
  transactionStore.clear();
});

describe('transaction-specific wallet approval', () => {
  test('requires explicit approval and returns a durable one-use receipt without storing raw proof material', async () => {
    const f = fixture();
    const challenge = await challengeFor(f);
    assert.equal(challenge.status, 200);
    assert.match(challenge.body.transactionCommitment, /^[0-9a-f]{64}$/);
    assert.match(challenge.body.message, /BIGKAIN TRANSACTION-SPECIFIC APPROVAL/);
    assert.match(challenge.body.message, new RegExp(challenge.body.transactionCommitment));
    assert.match(challenge.body.message, new RegExp(`${f.expected.destination} — 50000 sats`));
    assert.match(challenge.body.message, /Transaction fee: 1000 sats/);
    assert.match(challenge.body.message, /explicitly approve signing and submitting this exact transaction/);

    const stored = await transactionStore.getChallenge(challenge.body.challengeId);
    assert.equal(stored.messageHash.length, 64);
    assert.equal(stored.message, undefined);
    assert.equal(stored.signature, undefined);
    assert.equal(stored.psbt, undefined);

    const missingConfirmation = approvalRequest(f, challenge);
    delete missingConfirmation.explicitApproval;
    const rejected = await post(base, '/v1/btc/transaction/approve', missingConfirmation);
    assert.equal(rejected.status, 400);
    assert.match(rejected.body.error, /explicitApproval/);

    const result = await post(base, '/v1/btc/transaction/approve', approvalRequest(f, challenge));
    assert.equal(result.status, 200);
    assert.equal(result.body.approved, true);
    assert.equal(result.body.summary.transactionCommitment, challenge.body.transactionCommitment);
    assert.equal(result.body.summary.walletAddress, f.expected.walletAddress);
    assert.equal(result.body.summary.destination, f.expected.destination);
    assert.equal(result.body.summary.amountSats, f.expected.amountSats);
    assert.equal(result.body.summary.feeSats, 1000);
    assert.ok(Date.parse(result.body.approvedAt) > 0);
    assert.ok(Date.parse(result.body.expiresAt) > Date.now());
    assert.match(result.body.approvalId, /^bk_txapp_[0-9a-f]{32}$/);
    assert.match(result.body.walletAction, /connected wallet/);

    const consumed = await transactionStore.getChallenge(challenge.body.challengeId);
    assert.ok(consumed.consumedAt);
    assert.equal(consumed.approvalId, result.body.approvalId);
    assert.ok(consumed.approvedAt);
  });

  test('rejects a changed transaction without consuming the original challenge', async () => {
    const f = fixture();
    const challenge = await challengeFor(f);
    const other = fixture();
    const mismatch = await post(base, '/v1/btc/transaction/approve', approvalRequest(other, challenge));
    assert.equal(mismatch.status, 400);
    assert.match(mismatch.body.error, /does not match this PSBT/);

    const valid = await post(base, '/v1/btc/transaction/approve', approvalRequest(f, challenge));
    assert.equal(valid.status, 200);
  });

  test('atomically consumes a challenge once when separate router instances share the durable store', async () => {
    const f = fixture();
    const challenge = await challengeFor(f);
    const secondServer = makeApp({ store: transactionStore }).listen(0);
    await new Promise((resolve) => secondServer.once('listening', resolve));
    const secondBase = `http://127.0.0.1:${secondServer.address().port}`;
    try {
      const payload = approvalRequest(f, challenge);
      const replies = await Promise.all([
        post(base, '/v1/btc/transaction/approve', payload),
        post(secondBase, '/v1/btc/transaction/approve', payload),
      ]);
      assert.deepEqual(replies.map((reply) => reply.status).sort(), [200, 409]);
    } finally {
      await new Promise((resolve) => secondServer.close(resolve));
    }
  });

  test('a bad ownership signature consumes the challenge and replay is rejected', async () => {
    const f = fixture();
    const challenge = await challengeFor(f);
    const bad = await post(base, '/v1/btc/transaction/approve', approvalRequest(f, challenge, signedOwnershipProof('not the challenge message')));
    assert.equal(bad.status, 403);

    const replay = await post(base, '/v1/btc/transaction/approve', approvalRequest(f, challenge));
    assert.equal(replay.status, 409);
  });

  test('rejects signed PSBTs and unconfirmed inputs before issuing a challenge', async () => {
    const signedFixture = fixture();
    const signed = Psbt.fromBase64(signedFixture.psbtBase64);
    signed.signInput(0, { publicKey: pub, sign: (hash) => Buffer.from(ecc.sign(hash, priv)) });
    const signedChallenge = await post(base, '/v1/btc/ownership/challenge', {
      address: walletAddress,
      psbt: signed.toBase64(),
    });
    assert.equal(signedChallenge.status, 400);
    assert.match(signedChallenge.body.error, /unsigned PSBT/);

    const unconfirmedFixture = fixture();
    prevouts.get(unconfirmedFixture.prevTxid).confirmed = false;
    const unconfirmed = await challengeFor(unconfirmedFixture);
    assert.equal(unconfirmed.status, 400);
    assert.match(unconfirmed.body.error, /not confirmed/);
  });

  test('rejects unsafe sighash modes at both challenge and approval stages', async () => {
    for (const sighashType of [2, 3, 0x81, 0x82, 0x83]) {
      const f = fixture();
      const challenge = await challengeFor(f);
      const unsafe = Psbt.fromBase64(f.psbtBase64);
      unsafe.updateInput(0, { sighashType });
      const bad = { ...f, psbtBase64: unsafe.toBase64() };
      const issue = await challengeFor(bad);
      assert.equal(issue.status, 400);
      assert.match(issue.body.error, /SIGHASH/);
      const result = await post(base, '/v1/btc/transaction/approve', approvalRequest(f, challenge, undefined, bad.psbtBase64));
      assert.equal(result.status, 400);
      assert.match(result.body.error, /SIGHASH/);
      assert.equal((await transactionStore.getChallenge(challenge.body.challengeId)).consumedAt, null);
    }
  });

  test('accepts explicit SIGHASH_ALL but binds even safe metadata changes to a fresh approval', async () => {
    const f = fixture();
    const challenge = await challengeFor(f);
    const changed = Psbt.fromBase64(f.psbtBase64);
    changed.updateInput(0, { sighashType: Transaction.SIGHASH_ALL });
    const changedFixture = { ...f, psbtBase64: changed.toBase64() };
    const mismatch = await post(base, '/v1/btc/transaction/approve', approvalRequest(f, challenge, undefined, changedFixture.psbtBase64));
    assert.equal(mismatch.status, 400);
    assert.match(mismatch.body.error, /does not match this PSBT/);
    const fresh = await approve(changedFixture);
    assert.equal(fresh.result.status, 200);
  });

  test('rejects script-based signing policies and fees above the absolute cap', async () => {
    const f = fixture();
    const scripted = Psbt.fromBase64(f.psbtBase64);
    scripted.updateInput(0, { redeemScript: Buffer.from('51', 'hex') });
    const complex = await challengeFor({ ...f, psbtBase64: scripted.toBase64() });
    assert.equal(complex.status, 400);
    assert.match(complex.body.error, /single-key/);

    const large = fixture(300000);
    const original = Psbt.fromBase64(large.psbtBase64);
    const expensive = new Psbt();
    expensive.addInput({ ...original.txInputs[0], nonWitnessUtxo: original.data.inputs[0].nonWitnessUtxo });
    expensive.addOutput({ address: DESTINATION, value: 50000 });
    expensive.addOutput({ address: walletAddress, value: 100000 });
    const capped = await challengeFor({ ...large, psbtBase64: expensive.toBase64() });
    assert.equal(capped.status, 400);
    assert.match(capped.body.error, /1-100000 satoshis/);
  });

  test('fails closed when durable storage is unavailable and exposes no backend broadcast route', async () => {
    const f = fixture();
    const challenge = await post(disabledBase, '/v1/btc/ownership/challenge', {
      address: f.expected.walletAddress,
      psbt: f.psbtBase64,
    });
    assert.equal(challenge.status, 503);

    const approval = await post(disabledBase, '/v1/btc/transaction/approve', {});
    assert.equal(approval.status, 503);

    const broadcast = await post(base, '/v1/btc/transaction/broadcast', {
      approvalId: 'bk_txapp_' + '0'.repeat(32),
      transactionHex: '00',
    });
    assert.equal(broadcast.status, 404);
    assert.equal(broadcast.body.error, 'not found');
  });
});
