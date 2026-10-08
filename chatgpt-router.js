import { Router } from 'express';
import { randomBytes } from 'node:crypto';
import {
  buildUnsignedPsbt,
  containsKeyMaterial,
  getEvents,
  isValidAddress,
  validatePsbt,
  verifyOwnershipSignature,
} from './signer.js';
import { createMemoryOwnershipStore, hashOwnershipMessage } from './ownership-store.js';

const OWNERSHIP_TTL_MS = 10 * 60 * 1000;

function rejectKeyMaterial(req, res, next) {
  if (containsKeyMaterial(req.body)) {
    return res.status(400).json({
      error: 'request rejected: this backend never accepts seeds, mnemonics, or private keys',
    });
  }
  next();
}

function requireJsonString(value, name, allowEmpty = false) {
  if (typeof value !== 'string' || (!allowEmpty && !value)) {
    throw Object.assign(new Error(`${name} must be a string`), { status: 400 });
  }
}

function canUseLocalOwnershipChallenges() {
  return process.env.BIGKAIN_CHATGPT_ALLOW_EPHEMERAL_OWNERSHIP === 'true'
    && process.env.NODE_ENV !== 'production'
    && process.env.VERCEL !== '1';
}

export function createChatGptRouter({ mempool, mempoolBase, network = 'bitcoin-mainnet', ownershipStore = null }) {
  const router = Router();
  const ephemeralOwnershipStore = createMemoryOwnershipStore();
  const getOwnershipStore = () => {
    if (ownershipStore?.durable === true) return ownershipStore;
    return canUseLocalOwnershipChallenges() ? ephemeralOwnershipStore : null;
  };
  const requireOwnershipStore = (req, res, next) => {
    const store = getOwnershipStore();
    if (!store) {
      return res.status(503).json({
        valid: false,
        gated: true,
        reason: 'ownership proofs require a configured durable shared store; process-local mode is restricted to local non-production use',
      });
    }
    req.ownershipStore = store;
    next();
  };

  async function getUtxos(addr) {
    const utxos = await mempool(`/address/${addr}/utxo`);
    return utxos.map((u) => ({
      txid: u.txid,
      vout: u.vout,
      value: u.value,
      confirmed: !!(u.status && u.status.confirmed),
    }));
  }

  async function getPrevout(txid, vout) {
    const tx = await mempool(`/tx/${txid}`);
    const o = tx.vout && tx.vout[vout];
    if (!o) throw Object.assign(new Error('prevout not found'), { status: 502 });
    return { scriptHex: o.scriptpubkey, value: o.value };
  }

  async function getTxHex(txid) {
    const res = await fetch(`${mempoolBase || 'https://mempool.space/api'}/tx/${txid}/hex`);
    if (!res.ok) throw Object.assign(new Error(`mempool.space responded ${res.status}`), { status: 502 });
    return (await res.text()).trim();
  }

  router.use(rejectKeyMaterial);

  router.get('/status', async (_req, res) => {
    const store = getOwnershipStore();
    let ownershipStateAvailable = Boolean(store);
    let ownershipProof = store
      ? { status: 'RED', address: null, verified_at: null }
      : { status: 'UNAVAILABLE', reason: 'durable shared challenge state is not configured' };
    if (store) {
      try {
        const latest = await store.getLatestVerifiedProof();
        if (latest) {
          ownershipProof = {
            status: 'GREEN',
            address: latest.address,
            verified_at: latest.verifiedAt,
          };
        }
      } catch {
        ownershipStateAvailable = false;
        ownershipProof = { status: 'UNAVAILABLE', reason: 'durable ownership storage is temporarily unavailable' };
      }
    }

    res.json({
      ok: true,
      integration: 'chatgpt',
      service: 'bigkain-backend',
      network,
      signing_authority: 'BigKain',
      broadcast_authority: 'BigKain-or-approved-signer',
      chatgpt_can: [
        'read Bitcoin balance and UTXO data by address',
        'explain transactions and fees',
        'prepare unsigned PSBTs',
        'validate signer-produced PSBTs',
        'read workflow/security events',
        ...(ownershipStateAvailable ? [
          'initiate ownership-verification challenges',
          'submit signer-produced ownership proofs for verification',
        ] : []),
      ],
      chatgpt_unavailable: ownershipStateAvailable
        ? []
        : ['ownership challenge and verification require an available durable shared store; process-local mode is restricted to local non-production use'],
      chatgpt_cannot: [
        'receive seed phrases or private keys',
        'sign Bitcoin transactions',
        'approve spending',
        'bypass BigKain user approval',
        'broadcast transactions',
      ],
      ownership_proof: ownershipProof,
    });
  });

  router.get('/address/:address', async (req, res) => {
    const addr = req.params.address;
    if (!isValidAddress(addr)) return res.status(400).json({ error: 'invalid bitcoin address' });
    try {
      const info = await mempool(`/address/${addr}`);
      const funded = info.chain_stats?.funded_txo_sum || 0;
      const spent = info.chain_stats?.spent_txo_sum || 0;
      res.json({
        address: addr,
        balanceSats: funded - spent,
        fundedSats: funded,
        spentSats: spent,
        txCount: info.chain_stats?.tx_count || 0,
        mempool: {
          fundedSats: info.mempool_stats?.funded_txo_sum || 0,
          spentSats: info.mempool_stats?.spent_txo_sum || 0,
          txCount: info.mempool_stats?.tx_count || 0,
        },
        ownership_proof: getOwnershipStore()
          ? 'RED unless a valid cryptographic challenge proof exists'
          : 'UNAVAILABLE until durable shared challenge state is configured',
      });
    } catch (e) {
      res.status(e.status || 502).json({ error: e.message });
    }
  });

  router.get('/address/:address/utxos', async (req, res) => {
    const addr = req.params.address;
    if (!isValidAddress(addr)) return res.status(400).json({ error: 'invalid bitcoin address' });
    try {
      const utxos = await getUtxos(addr);
      res.json({
        address: addr,
        count: utxos.length,
        totalSats: utxos.reduce((sum, u) => sum + (u.value || 0), 0),
        utxos,
      });
    } catch (e) {
      res.status(e.status || 502).json({ error: e.message });
    }
  });

  router.get('/events', (req, res) => {
    const n = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
    const events = getEvents(n);
    res.json({ count: events.length, events });
  });

  router.post('/ownership/challenge', requireOwnershipStore, async (req, res) => {
    const { address } = req.body || {};
    if (!isValidAddress(address)) {
      return res.status(400).json({ error: 'address must be a valid bitcoin address' });
    }

    const addr = address.trim();
    const now = Date.now();
    const challengeId = 'bk_gpt_ch_' + randomBytes(16).toString('hex');
    const nonce = randomBytes(16).toString('hex');
    const expiresAt = new Date(now + OWNERSHIP_TTL_MS).toISOString();
    const message = [
      'BIGKAIN OWNERSHIP PROOF',
      `Address: ${addr}`,
      `Nonce: ${nonce}`,
      `Issued: ${new Date(now).toISOString()}`,
      `Expires: ${expiresAt}`,
      'Sign this message with the private key for the address above. Nothing moves; nothing broadcasts.',
    ].join('\n');

    try {
      await req.ownershipStore.pruneExpiredChallenges();
      await req.ownershipStore.createChallenge({
        challengeId,
        address: addr,
        messageHash: hashOwnershipMessage(message),
        expiresAt,
      });
    } catch {
      return res.status(503).json({
        valid: false,
        gated: true,
        reason: 'durable ownership storage is temporarily unavailable',
      });
    }

    res.json({ challengeId, address: addr, message, expiresAt, gated: true });
  });

  router.post('/ownership/verify', requireOwnershipStore, async (req, res) => {
    const { address, message, signature, challengeId } = req.body || {};
    try {
      requireJsonString(address, 'address');
      requireJsonString(message, 'message');
      requireJsonString(signature, 'signature');
      requireJsonString(challengeId, 'challengeId');
    } catch (e) {
      return res.status(e.status || 400).json({ valid: false, reason: e.message });
    }

    if (!isValidAddress(address)) {
      return res.status(400).json({ valid: false, reason: 'invalid bitcoin address' });
    }

    let c;
    try {
      c = await req.ownershipStore.getChallenge(challengeId);
    } catch {
      return res.status(503).json({ valid: false, gated: true, reason: 'durable ownership storage is temporarily unavailable' });
    }
    if (!c) return res.status(400).json({ valid: false, gated: true, reason: 'unknown or expired challenge' });
    if (Date.parse(c.expiresAt) <= Date.now()) {
      return res.status(400).json({ valid: false, gated: true, reason: 'unknown or expired challenge' });
    }
    if (c.consumedAt) return res.json({ valid: false, gated: true, reason: 'challenge already used (replay rejected)' });
    if (c.address !== address.trim()) return res.json({ valid: false, gated: true, reason: 'address does not match the issued challenge' });
    if (c.messageHash !== hashOwnershipMessage(message)) return res.json({ valid: false, gated: true, reason: 'message does not match the issued challenge' });

    let consumed;
    try {
      consumed = await req.ownershipStore.consumeChallenge(challengeId);
    } catch {
      return res.status(503).json({ valid: false, gated: true, reason: 'durable ownership storage is temporarily unavailable' });
    }
    if (!consumed) {
      let current;
      try {
        current = await req.ownershipStore.getChallenge(challengeId);
      } catch {
        return res.status(503).json({ valid: false, gated: true, reason: 'durable ownership storage is temporarily unavailable' });
      }
      if (current?.consumedAt) {
        return res.json({ valid: false, gated: true, reason: 'challenge already used (replay rejected)' });
      }
      return res.status(400).json({ valid: false, gated: true, reason: 'unknown or expired challenge' });
    }

    const result = verifyOwnershipSignature(address.trim(), message, signature);
    const response = {
      valid: result.valid,
      gated: true,
      address: address.trim(),
      challengeId,
      scheme: result.scheme,
      ...(result.reason ? { reason: result.reason } : {}),
    };

    if (result.valid) {
      try {
        const proof = await req.ownershipStore.markVerified(challengeId);
        if (!proof) {
          return res.status(503).json({ valid: false, gated: true, reason: 'verified ownership proof could not be durably recorded; request a new challenge' });
        }
      } catch {
        return res.status(503).json({ valid: false, gated: true, reason: 'verified ownership proof could not be durably recorded; request a new challenge' });
      }
    }

    res.json(response);
  });

  router.post('/transaction/prepare', async (req, res) => {
    const { walletAddress, destination, amountSats, feeRateSatVb } = req.body || {};
    if (!isValidAddress(walletAddress) || !isValidAddress(destination)) {
      return res.status(400).json({ error: 'walletAddress and destination must be valid bitcoin addresses' });
    }

    try {
      const built = await buildUnsignedPsbt(
        { walletAddress, destination, amountSats, feeRateSatVb },
        { getUtxos, getPrevout, getTxHex },
      );
      res.json({
        ...built,
        workflow: [
          'ChatGPT prepares and explains',
          'BigKain displays exact transaction details',
          'USER explicitly approves',
          'BigKain signer signs',
          'BigKain backend validates the signer-produced PSBT',
          'BigKain-or-approved-signer broadcasts',
          'real TXID is returned',
        ],
        approval_required: true,
        broadcast_by_chatgpt: false,
        signing_by_chatgpt: false,
      });
    } catch (e) {
      res.status(e.status || 502).json({ error: e.message });
    }
  });

  router.post('/transaction/validate', (req, res) => {
    const { psbt, expected } = req.body || {};
    if (typeof psbt !== 'string' || !psbt || !expected || typeof expected !== 'object') {
      return res.status(400).json({
        valid: false,
        verdict: 'REJECT',
        reasons: ['body must include psbt and expected'],
      });
    }

    const result = validatePsbt(psbt, expected);
    res.json({
      ...result,
      approval_required: true,
      broadcast_by_chatgpt: false,
      signing_by_chatgpt: false,
    });
  });

  // Deliberately no /transaction/sign or /transaction/broadcast route.
  return router;
}
