import { neon } from '@neondatabase/serverless';
import { createHash } from 'node:crypto';

export function hashOwnershipMessage(message) {
  return createHash('sha256').update(message, 'utf8').digest('hex');
}

function toIso(value) {
  if (value == null) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toISOString();
}

function mapChallengeRow(row) {
  if (!row) return null;
  return {
    challengeId: row.challenge_id,
    address: row.address,
    messageHash: row.message_sha256,
    expiresAt: toIso(row.expires_at),
    consumedAt: toIso(row.consumed_at),
    verifiedAt: toIso(row.verified_at),
  };
}

function mapProofRow(row) {
  if (!row) return null;
  return { address: row.address, verifiedAt: toIso(row.verified_at) };
}

/**
 * Process-local store for explicit local non-production opt-in only.
 * Production and Vercel routes use createNeonOwnershipStore or fail closed.
 */
export function createMemoryOwnershipStore() {
  const records = new Map();
  let latestProof = null;

  return {
    durable: false,

    async pruneExpiredChallenges() {
      const now = Date.now();
      for (const [id, record] of records) {
        if (!record.verifiedAt && Date.parse(record.expiresAt) <= now) records.delete(id);
      }
    },

    async createChallenge({ challengeId, address, messageHash, expiresAt }) {
      if (records.has(challengeId)) throw new Error('duplicate ownership challenge id');
      records.set(challengeId, {
        challengeId,
        address,
        messageHash,
        expiresAt: toIso(expiresAt),
        consumedAt: null,
        verifiedAt: null,
      });
    },

    async getChallenge(challengeId) {
      const record = records.get(challengeId);
      return record ? { ...record } : null;
    },

    async consumeChallenge(challengeId) {
      const record = records.get(challengeId);
      if (!record || record.consumedAt || Date.parse(record.expiresAt) <= Date.now()) return null;
      record.consumedAt = new Date().toISOString();
      return { ...record };
    },

    async markVerified(challengeId) {
      const record = records.get(challengeId);
      if (!record?.consumedAt || record.verifiedAt) return null;
      record.verifiedAt = new Date().toISOString();
      latestProof = { address: record.address, verifiedAt: record.verifiedAt };
      return { ...latestProof };
    },

    async getLatestVerifiedProof() {
      return latestProof ? { ...latestProof } : null;
    },
  };
}

/**
 * Neon/Postgres store. Consumption is a single conditional UPDATE using the
 * database clock, so parallel Vercel instances cannot both claim one challenge.
 * The raw message, signature, and any key material are never persisted.
 */
export function createNeonOwnershipStore(connectionString, { sqlFactory = neon } = {}) {
  if (typeof connectionString !== 'string' || !connectionString) {
    throw new TypeError('a Neon connection string is required');
  }
  const sql = sqlFactory(connectionString);

  return {
    durable: true,

    async pruneExpiredChallenges() {
      await sql`
        DELETE FROM public.bigkain_ownership_challenges
        WHERE expires_at <= clock_timestamp() AND verified_at IS NULL
      `;
    },

    async createChallenge({ challengeId, address, messageHash, expiresAt }) {
      await sql`
        INSERT INTO public.bigkain_ownership_challenges
          (challenge_id, address, message_sha256, expires_at)
        VALUES (${challengeId}, ${address}, ${messageHash}, ${expiresAt})
      `;
    },

    async getChallenge(challengeId) {
      const rows = await sql`
        SELECT challenge_id, address, message_sha256, expires_at, consumed_at, verified_at
        FROM public.bigkain_ownership_challenges
        WHERE challenge_id = ${challengeId}
        LIMIT 1
      `;
      return mapChallengeRow(rows[0]);
    },

    async consumeChallenge(challengeId) {
      const rows = await sql`
        UPDATE public.bigkain_ownership_challenges
        SET consumed_at = clock_timestamp()
        WHERE challenge_id = ${challengeId}
          AND consumed_at IS NULL
          AND expires_at > clock_timestamp()
        RETURNING challenge_id, address, message_sha256, expires_at, consumed_at, verified_at
      `;
      return mapChallengeRow(rows[0]);
    },

    async markVerified(challengeId) {
      const rows = await sql`
        UPDATE public.bigkain_ownership_challenges
        SET verified_at = clock_timestamp()
        WHERE challenge_id = ${challengeId}
          AND consumed_at IS NOT NULL
          AND verified_at IS NULL
        RETURNING address, verified_at
      `;
      return mapProofRow(rows[0]);
    },

    async getLatestVerifiedProof() {
      const rows = await sql`
        SELECT address, verified_at
        FROM public.bigkain_ownership_challenges
        WHERE verified_at IS NOT NULL
        ORDER BY verified_at DESC
        LIMIT 1
      `;
      return mapProofRow(rows[0]);
    },
  };
}
