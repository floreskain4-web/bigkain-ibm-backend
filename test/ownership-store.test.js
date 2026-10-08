import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  createMemoryOwnershipStore,
  createNeonOwnershipStore,
  hashOwnershipMessage,
} from '../ownership-store.js';

const challenge = (overrides = {}) => ({
  challengeId: 'bk_gpt_ch_' + 'a'.repeat(32),
  address: '1BitcoinAddressForTesting1234567890',
  messageHash: hashOwnershipMessage('BIGKAIN OWNERSHIP PROOF\nNonce: test'),
  expiresAt: new Date(Date.now() + 60_000).toISOString(),
  ...overrides,
});

describe('ownership challenge stores', () => {
  test('hashes the exact UTF-8 challenge message without exposing it', () => {
    const message = 'BIGKAIN OWNERSHIP PROOF\nNonce: 0123456789abcdef';
    const digest = hashOwnershipMessage(message);
    assert.match(digest, /^[0-9a-f]{64}$/);
    assert.notEqual(digest, hashOwnershipMessage(message + ' '));
    assert.equal(digest.includes('0123456789abcdef'), false);
  });

  test('memory store allows one concurrent consumer and keeps successful proof state', async () => {
    const store = createMemoryOwnershipStore();
    const record = challenge();
    await store.createChallenge(record);

    const claims = await Promise.all([
      store.consumeChallenge(record.challengeId),
      store.consumeChallenge(record.challengeId),
    ]);
    assert.equal(claims.filter(Boolean).length, 1);
    assert.ok(claims.find(Boolean).consumedAt);

    const proof = await store.markVerified(record.challengeId);
    assert.equal(proof.address, record.address);
    assert.ok(Date.parse(proof.verifiedAt));
    assert.deepEqual(await store.getLatestVerifiedProof(), proof);

    const stored = await store.getChallenge(record.challengeId);
    assert.equal('message' in stored, false);
    assert.equal('signature' in stored, false);
    assert.equal('privateKey' in stored, false);
  });

  test('expired challenges cannot be consumed and are pruned without deleting verified proofs', async () => {
    const store = createMemoryOwnershipStore();
    const expired = challenge({
      challengeId: 'bk_gpt_ch_' + 'b'.repeat(32),
      expiresAt: new Date(Date.now() - 1_000).toISOString(),
    });
    await store.createChallenge(expired);
    assert.equal(await store.consumeChallenge(expired.challengeId), null);
    await store.pruneExpiredChallenges();
    assert.equal(await store.getChallenge(expired.challengeId), null);
  });

  test('Neon challenge claim is one parameterized UPDATE guarded by the database clock', async () => {
    const calls = [];
    const row = {
      challenge_id: 'bk_gpt_ch_' + 'c'.repeat(32),
      address: '1BitcoinAddressForTesting1234567890',
      message_sha256: 'd'.repeat(64),
      expires_at: '2026-10-08T03:00:00.000Z',
      consumed_at: '2026-10-08T02:55:00.000Z',
      verified_at: null,
    };
    const sqlFactory = () => async (strings, ...values) => {
      const text = strings.join(' ? ');
      calls.push({ text, values });
      return text.includes('SET consumed_at = clock_timestamp()') ? [row] : [];
    };
    const store = createNeonOwnershipStore('postgresql://test.invalid/neondb', { sqlFactory });
    const result = await store.consumeChallenge(row.challenge_id);

    assert.equal(result.challengeId, row.challenge_id);
    assert.equal(result.consumedAt, '2026-10-08T02:55:00.000Z');
    const claim = calls[0];
    assert.match(claim.text, /UPDATE public\.bigkain_ownership_challenges/);
    assert.match(claim.text, /consumed_at IS NULL/);
    assert.match(claim.text, /expires_at > clock_timestamp\(\)/);
    assert.match(claim.text, /RETURNING/);
    assert.deepEqual(claim.values, [row.challenge_id]);
  });

  test('Neon proof finalization only marks a consumed, not-yet-verified challenge', async () => {
    const calls = [];
    const sqlFactory = () => async (strings, ...values) => {
      const text = strings.join(' ? ');
      calls.push({ text, values });
      return [{ address: '1BitcoinAddressForTesting1234567890', verified_at: '2026-10-08T02:56:00.000Z' }];
    };
    const store = createNeonOwnershipStore('postgresql://test.invalid/neondb', { sqlFactory });
    const proof = await store.markVerified('bk_gpt_ch_' + 'd'.repeat(32));

    assert.equal(proof.address, '1BitcoinAddressForTesting1234567890');
    assert.match(calls[0].text, /consumed_at IS NOT NULL/);
    assert.match(calls[0].text, /verified_at IS NULL/);
    assert.deepEqual(calls[0].values, ['bk_gpt_ch_' + 'd'.repeat(32)]);
  });
});
