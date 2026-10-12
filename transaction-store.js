import { neon } from '@neondatabase/serverless';

function toIso(value) {
  if (value == null) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toISOString();
}

function mapChallengeRow(row) {
  if (!row) return null;
  return {
    challengeId: row.challenge_id,
    walletAddress: row.wallet_address,
    messageHash: row.message_sha256,
    transactionCommitment: row.transaction_commitment,
    expiresAt: toIso(row.expires_at),
    consumedAt: toIso(row.consumed_at),
    approvalId: row.approval_id || null,
    approvedAt: toIso(row.approved_at),
  };
}

/**
 * Process-local store for tests and explicit local use only. Production Vercel
 * wiring uses the Neon store so conditional updates are atomic across instances.
 */
export function createMemoryTransactionStore() {
  const challenges = new Map();

  return {
    durable: false,

    async createChallenge(record) {
      if (challenges.has(record.challengeId)) throw new Error('duplicate transaction challenge id');
      challenges.set(record.challengeId, { ...record, consumedAt: null, approvalId: null, approvedAt: null });
    },

    async getChallenge(challengeId) {
      const record = challenges.get(challengeId);
      return record ? { ...record } : null;
    },

    async consumeChallenge(challengeId) {
      const record = challenges.get(challengeId);
      if (!record || record.consumedAt || Date.parse(record.expiresAt) <= Date.now()) return null;
      record.consumedAt = new Date().toISOString();
      return { ...record };
    },

    async markApproved(challengeId, approvalId) {
      const record = challenges.get(challengeId);
      if (!record?.consumedAt || record.approvedAt || record.approvalId) return null;
      record.approvalId = approvalId;
      record.approvedAt = new Date().toISOString();
      return { approvalId, approvedAt: record.approvedAt };
    },

    clear() {
      challenges.clear();
    },
  };
}

/**
 * Neon/Postgres store. Challenge consumption uses a conditional UPDATE with the
 * database clock, so separate Vercel instances cannot both accept one proof.
 * Only public address/transaction data and a hash of the exact message persist;
 * the message, signature, PSBT, and all key material are never stored.
 */
export function createNeonTransactionStore(connectionString, { sqlFactory = neon } = {}) {
  if (typeof connectionString !== 'string' || !connectionString) {
    throw new TypeError('a Neon connection string is required');
  }
  const sql = sqlFactory(connectionString);

  return {
    durable: true,

    async createChallenge({ challengeId, walletAddress, messageHash, transactionCommitment, expiresAt }) {
      await sql`
        INSERT INTO public.bigkain_btc_approval_challenges
          (challenge_id, wallet_address, message_sha256, transaction_commitment, expires_at)
        VALUES (${challengeId}, ${walletAddress}, ${messageHash}, ${transactionCommitment}, ${expiresAt})
      `;
    },

    async getChallenge(challengeId) {
      const rows = await sql`
        SELECT challenge_id, wallet_address, message_sha256, transaction_commitment,
               expires_at, consumed_at, approval_id, approved_at
        FROM public.bigkain_btc_approval_challenges
        WHERE challenge_id = ${challengeId}
        LIMIT 1
      `;
      return mapChallengeRow(rows[0]);
    },

    async consumeChallenge(challengeId) {
      const rows = await sql`
        UPDATE public.bigkain_btc_approval_challenges
        SET consumed_at = clock_timestamp()
        WHERE challenge_id = ${challengeId}
          AND consumed_at IS NULL
          AND expires_at > clock_timestamp()
        RETURNING challenge_id, wallet_address, message_sha256, transaction_commitment,
                  expires_at, consumed_at, approval_id, approved_at
      `;
      return mapChallengeRow(rows[0]);
    },

    async markApproved(challengeId, approvalId) {
      const rows = await sql`
        UPDATE public.bigkain_btc_approval_challenges
        SET approval_id = ${approvalId}, approved_at = clock_timestamp()
        WHERE challenge_id = ${challengeId}
          AND consumed_at IS NOT NULL
          AND approved_at IS NULL
          AND approval_id IS NULL
        RETURNING approval_id, approved_at
      `;
      const row = rows[0];
      return row ? { approvalId: row.approval_id, approvedAt: toIso(row.approved_at) } : null;
    },
  };
}
