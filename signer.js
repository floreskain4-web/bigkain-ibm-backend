/**
 * signer.js — "WebView Backend Signer" endpoint set for bigkain-ibm-backend.
 *
 * Non-custodial by construction:
 *   - The backend verifies signatures and enforces policy. It NEVER receives,
 *     stores, or logs seeds, mnemonics, xprvs, or private keys.
 *   - It builds UNSIGNED PSBTs only. It never signs and never broadcasts.
 *     There is deliberately NO broadcast endpoint.
 *
 * Sessions and challenges live in memory, expire quickly, and challenges are
 * single-use (replay protection).
 */

import { Router } from 'express';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Psbt, Transaction, networks, address } from 'bitcoinjs-lib';
import bitcoreMessage from 'bitcoinjs-message';
import { Verifier as Bip322Verifier } from 'bip322-js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const NETWORK = networks.bitcoin;
const SESSION_TTL_MS = 10 * 60 * 1000;
const SIGNER_CHALLENGE_TTL_MS = 5 * 60 * 1000;
const OWNERSHIP_CHALLENGE_TTL_MS = 10 * 60 * 1000;
const DUST_SATS = 546;

// Same loose address check as server.js: P2PKH (1...), P2SH (3...), bech32 (bc1q...), bech32m (bc1p...)
const ADDR_RE = /^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$/;
export function isValidAddress(addr) {
  return typeof addr === 'string' && ADDR_RE.test(addr.trim());
}

// ---------------------------------------------------------------------------
// Key-material guard: reject any request whose field names look like key
// material, or whose values look like WIF-encoded private keys. bitcoinjs
// message signatures are base64 (~88 chars) and never match the WIF pattern.
// ---------------------------------------------------------------------------
const KEY_FIELD_RE = /(seed|mnemonic|xprv|extended[_-]?private|private[_-]?key|seed[_-]?phrase|^wif$|hd[_-]?seed|bip39|passphrase)/i;
const WIF_RE = /^[5KLc][1-9A-HJ-NP-Za-km-z]{50,51}$/;

export function containsKeyMaterial(obj) {
  if (!obj || typeof obj !== 'object') return false;
  for (const [k, v] of Object.entries(obj)) {
    if (KEY_FIELD_RE.test(k)) return true;
    if (typeof v === 'string' && WIF_RE.test(v.trim())) return true;
    if (v && typeof v === 'object' && containsKeyMaterial(v)) return true;
  }
  return false;
}

function keyGuard(req, res, next) {
  if (containsKeyMaterial(req.body)) {
    return res.status(400).json({
      error: 'request rejected: this backend never accepts seeds, mnemonics, or private keys',
    });
  }
  next();
}

// ---------------------------------------------------------------------------
// Shared ownership-signature verification (bitcoinjs-message, base58 only).
// Same behavior as the legacy /verify-ownership endpoint.
// ---------------------------------------------------------------------------
export function verifyOwnershipMessage(address, message, signature) {
  const addr = (address || '').trim();
  if (addr.startsWith('bc1')) {
    return { valid: false, reason: 'bech32 (bc1...) signatures use BIP-322 and are not supported by this endpoint; use a base58 (1.../3...) address' };
  }
  try {
    const valid = bitcoreMessage.verify(message, addr, signature);
    return { valid };
  } catch (e) {
    return { valid: false, reason: e.message };
  }
}

// ---------------------------------------------------------------------------
// Script / address helpers (mainnet only)
// ---------------------------------------------------------------------------
export function scriptTypeOfAddress(addr) {
  const a = addr.trim();
  if (a[0] === '1') return 'p2pkh';
  if (a[0] === '3') return 'p2sh';
  if (a.startsWith('bc1q') || a.startsWith('BC1Q')) {
    const d = address.fromBech32(a.toLowerCase());
    return d.data.length === 20 ? 'p2wpkh' : 'p2wsh';
  }
  if (a.startsWith('bc1p') || a.startsWith('BC1P')) return 'p2tr';
  return null;
}

function addressFromScript(script) {
  // Throws on non-mainnet or unknown scripts — callers treat that as invalid.
  return address.fromOutputScript(script, NETWORK);
}

const INPUT_VSIZE = { p2pkh: 148, p2sh: 91, p2wpkh: 68, p2wsh: 105, p2tr: 58 };
const OUTPUT_VSIZE = { p2pkh: 34, p2sh: 32, p2wpkh: 31, p2wsh: 43, p2tr: 43 };

function estimateVsize(inputTypes, outputTypes) {
  let v = 10;
  for (const t of inputTypes) v += INPUT_VSIZE[t] || 148;
  for (const t of outputTypes) v += OUTPUT_VSIZE[t] || 34;
  return v;
}

function isSegwitScriptType(t) {
  return t === 'p2wpkh' || t === 'p2wsh' || t === 'p2tr';
}

// ---------------------------------------------------------------------------
// Unsigned PSBT builder. deps: { getUtxos(addr), getPrevout(txid, vout),
// getTxHex(txid) }. Never touches key material.
// ---------------------------------------------------------------------------
export async function buildUnsignedPsbt({ walletAddress, destination, amountSats, feeRateSatVb }, deps) {
  const wallet = walletAddress.trim();
  const dest = destination.trim();

  if (!Number.isInteger(amountSats) || amountSats <= 0) {
    throw Object.assign(new Error('amountSats must be a positive integer'), { status: 400 });
  }
  if (typeof feeRateSatVb !== 'number' || !(feeRateSatVb >= 1) || feeRateSatVb > 1000) {
    throw Object.assign(new Error('feeRateSatVb must be a number between 1 and 1000'), { status: 400 });
  }

  const walletType = scriptTypeOfAddress(wallet);
  const destType = scriptTypeOfAddress(dest);
  if (!walletType || !destType) {
    throw Object.assign(new Error('unsupported address type'), { status: 400 });
  }

  const utxos = (await deps.getUtxos(wallet)).filter((u) => u.confirmed !== false);
  const sorted = utxos.slice().sort((a, b) => a.value - b.value);

  // Smallest-first coin selection, re-estimating the fee as inputs grow.
  const selected = [];
  let total = 0;
  let fee = 0;
  for (const u of sorted) {
    selected.push(u);
    total += u.value;
    const vsize = estimateVsize(
      selected.map(() => walletType),
      [destType, walletType],
    );
    fee = Math.ceil(vsize * feeRateSatVb);
    if (total >= amountSats + fee) break;
  }
  if (total < amountSats + fee) {
    throw Object.assign(new Error('insufficient confirmed funds'), { status: 400 });
  }

  let change = total - amountSats - fee;
  const outputs = [{ address: dest, sats: amountSats }];
  if (change >= DUST_SATS) {
    outputs.push({ address: wallet, sats: change, change: true });
  } else {
    fee += change; // dust change is donated to the fee
    change = 0;
  }

  const psbt = new Psbt({ network: NETWORK });
  psbt.setVersion(2);

  const inputs = [];
  for (const u of selected) {
    const prevout = await deps.getPrevout(u.txid, u.vout);
    const input = {
      hash: Buffer.from(u.txid, 'hex').reverse(),
      index: u.vout,
      sequence: 0xfffffffd, // RBF signaled
    };
    if (isSegwitScriptType(walletType)) {
      input.witnessUtxo = {
        script: Buffer.from(prevout.scriptHex, 'hex'),
        value: prevout.value,
      };
    } else {
      // Legacy (P2PKH/P2SH) inputs need the full previous transaction.
      input.nonWitnessUtxo = Buffer.from(await deps.getTxHex(u.txid), 'hex');
    }
    psbt.addInput(input);
    inputs.push({ txid: u.txid, vout: u.vout, value: u.value });
  }

  for (const o of outputs) {
    psbt.addOutput({ address: o.address, value: o.sats });
  }

  return {
    psbt: psbt.toBase64(),
    inputs,
    outputs: outputs.map((o) => ({ address: o.address, sats: o.sats, ...(o.change ? { change: true } : {}) })),
    feeSats: fee,
    changeSats: change,
  };
}

// ---------------------------------------------------------------------------
// PSBT validator. Checks a (possibly signed) PSBT against expectations.
// Returns { valid, verdict: 'SAFE_HOLD' | 'REJECT', reasons[] }.
// ---------------------------------------------------------------------------
export function validatePsbt(psbtBase64, expected) {
  const reasons = [];
  let psbt;
  try {
    if (typeof psbtBase64 !== 'string' || !psbtBase64) throw new Error('empty');
    psbt = Psbt.fromBase64(psbtBase64);
  } catch (e) {
    return { valid: false, verdict: 'REJECT', reasons: ['invalid PSBT encoding'] };
  }

  const { destination, amountSats, walletAddress, feeRateSatVb } = expected || {};
  if (!isValidAddress(destination) || !isValidAddress(walletAddress) ||
      !Number.isInteger(amountSats) || amountSats <= 0) {
    return { valid: false, verdict: 'REJECT', reasons: ['expected must include destination, walletAddress, and a positive integer amountSats'] };
  }
  const dest = destination.trim();
  const wallet = walletAddress.trim();

  // 1. Every input must carry a signature (partial or finalized).
  const unsigned = [];
  psbt.data.inputs.forEach((inp, i) => {
    const sigs = inp.partialSig || [];
    if (!sigs.length && !inp.finalScriptSig && !inp.finalScriptWitness) unsigned.push(i);
  });
  if (unsigned.length) reasons.push(`unsigned inputs: ${unsigned.join(',')}`);

  // 2. Every input must belong to the wallet address.
  let inputSum = 0;
  psbt.data.inputs.forEach((inp, i) => {
    try {
      let script;
      let value;
      if (inp.witnessUtxo) {
        script = inp.witnessUtxo.script;
        value = Number(inp.witnessUtxo.value);
      } else if (inp.nonWitnessUtxo) {
        const prevTx = Transaction.fromHex(inp.nonWitnessUtxo.toString('hex'));
        const idx = psbt.txInputs[i].index;
        const out = prevTx.outs[idx];
        script = out.script;
        value = Number(out.value);
      } else {
        reasons.push(`input ${i}: missing UTXO data`);
        return;
      }
      inputSum += value;
      const addr = addressFromScript(script);
      if (addr !== wallet) reasons.push(`input ${i} spends ${addr}, not wallet ${wallet}`);
    } catch (e) {
      reasons.push(`input ${i}: cannot resolve (${e.message})`);
    }
  });

  // 3. Outputs: exactly one payment of expected amount to destination;
  //    every other output must be change back to the wallet. Mainnet only.
  let outputSum = 0;
  let destPaid = 0;
  psbt.txOutputs.forEach((o, i) => {
    let addr;
    try {
      addr = addressFromScript(o.script);
    } catch (e) {
      reasons.push(`output ${i}: non-mainnet or unknown script`);
      return;
    }
    outputSum += Number(o.value);
    if (addr === dest && Number(o.value) === amountSats) {
      destPaid += 1;
    } else if (addr === wallet) {
      // change — allowed
    } else {
      reasons.push(`output ${i}: unexpected payment of ${o.value} sats to ${addr}`);
    }
  });
  if (destPaid !== 1) {
    reasons.push(`expected destination ${dest} to receive exactly one output of ${amountSats} sats`);
  }

  // 4. Fee sanity.
  const fee = inputSum - outputSum;
  if (fee < 0) {
    reasons.push('outputs exceed inputs (negative fee)');
  } else {
    const inputTypes = psbt.data.inputs.map((inp) => {
      try {
        const s = inp.witnessUtxo ? inp.witnessUtxo.script : null;
        if (s) {
          if (s[0] === 0x00 && s[1] === 0x14) return 'p2wpkh';
          if (s[0] === 0x00 && s[1] === 0x20) return 'p2wsh';
          if (s[0] === 0x51 && s[1] === 0x20) return 'p2tr';
        }
        return 'p2pkh';
      } catch { return 'p2pkh'; }
    });
    const outputTypes = psbt.txOutputs.map((o) => {
      try {
        const a = addressFromScript(o.script);
        return scriptTypeOfAddress(a);
      } catch { return 'p2pkh'; }
    });
    const vsize = estimateVsize(inputTypes, outputTypes);
    const rate = fee / vsize;
    if (!(rate >= 1) || rate > 1000) {
      reasons.push(`fee rate ${rate.toFixed(2)} sat/vB outside sane bounds (1-1000)`);
    }
    if (feeRateSatVb != null && (typeof feeRateSatVb !== 'number' || rate < feeRateSatVb / 3 || rate > feeRateSatVb * 3)) {
      reasons.push(`fee rate ${rate.toFixed(2)} sat/vB deviates from expected ${feeRateSatVb} sat/vB`);
    }
  }

  const valid = reasons.length === 0;
  return { valid, verdict: valid ? 'SAFE_HOLD' : 'REJECT', reasons };
}

// ---------------------------------------------------------------------------
// In-memory stores (single process; Code Engine runs one instance per revision)
// ---------------------------------------------------------------------------
const sessions = new Map();            // sessionId -> session
const signerChallenges = new Map();    // challengeId -> challenge
const ownershipChallenges = new Map(); // challengeId -> { challengeId, address, message, expiresAt, used }
const receipts = [];                   // in-memory receipt log
// Merged layout: signer.js lives at the backend root, so the log sits beside it.
// (Previously path.join(__dirname, '..', 'receipts.jsonl') when under src/.)
const RECEIPT_LOG = path.join(__dirname, 'receipts.jsonl');

function sweep(map) {
  const now = Date.now();
  for (const [k, v] of map) {
    if (Date.parse(v.expiresAt) <= now) map.delete(k);
  }
}

function getSession(sessionId) {
  sweep(sessions);
  return sessions.get(sessionId) || null;
}

function getChallenge(map, challengeId) {
  sweep(map);
  return map.get(challengeId) || null;
}

function sanitizeMeta(meta) {
  if (!meta || typeof meta !== 'object' || Array.isArray(meta)) return {};
  const out = {};
  for (const [k, v] of Object.entries(meta).slice(0, 50)) {
    if (typeof k !== 'string' || k.length > 128) continue;
    if (v == null || typeof v === 'number' || typeof v === 'boolean') out[k] = v;
    else if (typeof v === 'string') out[k] = v.slice(0, 4096);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Audit event ring buffer (in-memory, last 200 entries).
// NEVER log message text, signatures, or PSBTs — addresses, amounts,
// booleans, and truncated ids only.
// ---------------------------------------------------------------------------
const EVENTS_MAX = 200;
const events = [];

export function logEvent(type, detail) {
  events.push({ ts: new Date().toISOString(), type, detail: detail || {} });
  if (events.length > EVENTS_MAX) events.splice(0, events.length - EVENTS_MAX);
}

export function getEvents(limit) {
  let n = Number.isFinite(limit) ? Math.floor(limit) : 50;
  if (n <= 0) n = 50;
  n = Math.min(n, EVENTS_MAX);
  return events.slice(-n).reverse(); // newest first
}

// ---------------------------------------------------------------------------
// Router factory. deps: { mempool(path), mempoolBase } — the server's
// mempool.space helper.
// ---------------------------------------------------------------------------
export function createSignerRouter(deps) {
  const router = Router();

  async function getUtxos(addr) {
    const utxos = await deps.mempool(`/address/${addr}/utxo`);
    return utxos.map((u) => ({
      txid: u.txid,
      vout: u.vout,
      value: u.value,
      confirmed: !!(u.status && u.status.confirmed),
    }));
  }

  async function getPrevout(txid, vout) {
    const tx = await deps.mempool(`/tx/${txid}`);
    const o = tx.vout && tx.vout[vout];
    if (!o) throw Object.assign(new Error('prevout not found'), { status: 502 });
    return { scriptHex: o.scriptpubkey, value: o.value };
  }

  async function getTxHex(txid) {
    const res = await fetch(`${deps.mempoolBase || 'https://mempool.space/api'}/tx/${txid}/hex`);
    if (!res.ok) throw Object.assign(new Error(`mempool.space responded ${res.status}`), { status: 502 });
    return (await res.text()).trim();
  }

  // --- POST /v1/signer/session -------------------------------------------
  router.post('/v1/signer/session', keyGuard, (req, res) => {
    const { walletAddress, purpose } = req.body || {};
    if (!isValidAddress(walletAddress)) {
      return res.status(400).json({ error: 'walletAddress must be a valid bitcoin address' });
    }
    if (typeof purpose !== 'string' || !purpose.trim() || purpose.length > 64) {
      return res.status(400).json({ error: 'purpose must be a non-empty string (max 64 chars)' });
    }
    const now = Date.now();
    const sessionId = 'bk_sess_' + randomBytes(16).toString('hex');
    const session = {
      sessionId,
      walletAddress: walletAddress.trim(),
      purpose: purpose.trim(),
      status: 'PENDING_APPROVAL',
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + SESSION_TTL_MS).toISOString(),
    };
    sessions.set(sessionId, session);
    return res.json(session);
  });

  // --- POST /v1/signer/challenge -----------------------------------------
  router.post('/v1/signer/challenge', keyGuard, (req, res) => {
    const { sessionId } = req.body || {};
    if (typeof sessionId !== 'string' || !sessionId) {
      return res.status(400).json({ error: 'sessionId is required' });
    }
    const session = getSession(sessionId);
    if (!session) {
      return res.status(404).json({ error: 'session not found or expired' });
    }
    const now = Date.now();
    const challenge = {
      challengeId: 'bk_ch_' + randomBytes(16).toString('hex'),
      sessionId: session.sessionId,
      nonce: 'BK-' + randomBytes(16).toString('hex'),
      purpose: session.purpose,
      walletAddress: session.walletAddress,
      expiresAt: new Date(now + SIGNER_CHALLENGE_TTL_MS).toISOString(),
      used: false,
    };
    signerChallenges.set(challenge.challengeId, challenge);
    logEvent('signer.challenge', { sessionId: session.sessionId.slice(0, 20) + '…' });
    const { used, sessionId: sid, ...pub } = challenge;
    return res.json(pub);
  });

  // --- POST /v1/btc/ownership/challenge ----------------------------------
  router.post('/v1/btc/ownership/challenge', keyGuard, (req, res) => {
    const { address } = req.body || {};
    if (!isValidAddress(address)) {
      return res.status(400).json({ error: 'address must be a valid bitcoin address' });
    }
    const now = Date.now();
    const expiresAt = new Date(now + OWNERSHIP_CHALLENGE_TTL_MS).toISOString();
    const nonce = randomBytes(16).toString('hex');
    const message = [
      'BIGKAIN OWNERSHIP PROOF',
      `Address: ${address.trim()}`,
      `Nonce: ${nonce}`,
      `Issued: ${new Date(now).toISOString()}`,
      `Expires: ${expiresAt}`,
      'Sign this message with the private key for the address above. Nothing moves; nothing broadcasts.',
    ].join('\n');
    const challengeId = 'bk_ch_' + randomBytes(16).toString('hex');
    ownershipChallenges.set(challengeId, {
      challengeId,
      address: address.trim(),
      message,
      expiresAt,
      used: false,
    });
    return res.json({ challengeId, address: address.trim(), message, expiresAt });
  });

  // --- POST /v1/btc/ownership/verify -------------------------------------
  router.post('/v1/btc/ownership/verify', keyGuard, (req, res) => {
    const { address, message, signature, challengeId } = req.body || {};
    if (!isValidAddress(address) || typeof message !== 'string' || !message ||
        typeof signature !== 'string' || !signature) {
      return res.status(400).json({ valid: false, reason: 'body must include address, message, and signature' });
    }
    const addr = address.trim();
    if (challengeId != null) {
      if (typeof challengeId !== 'string' || !challengeId) {
        return res.status(400).json({ valid: false, reason: 'challengeId must be a string' });
      }
      const c = getChallenge(ownershipChallenges, challengeId);
      if (!c) {
        return res.status(400).json({ valid: false, reason: 'unknown or expired challenge' });
      }
      if (c.used) {
        logEvent('ownership.verify', { address: addr, valid: false, challengeId });
        return res.json({ valid: false, address: addr, challengeId, reason: 'challenge already used (replay rejected)' });
      }
      if (c.address !== addr || c.message !== message) {
        logEvent('ownership.verify', { address: addr, valid: false, challengeId });
        return res.json({ valid: false, address: addr, challengeId, reason: 'message/address does not match the issued challenge' });
      }
      c.used = true; // single-use: replay protection
    }
    const r = verifyOwnershipMessage(addr, message, signature);
    logEvent('ownership.verify', { address: addr, valid: r.valid, ...(challengeId ? { challengeId } : {}) });
    return res.json({ valid: r.valid, address: addr, ...(r.reason ? { reason: r.reason } : {}), ...(challengeId ? { challengeId } : {}) });
  });

  // --- POST /v1/btc/psbt/prepare ------------------------------------------
  router.post('/v1/btc/psbt/prepare', keyGuard, async (req, res) => {
    const { walletAddress, destination, amountSats, feeRateSatVb } = req.body || {};
    if (!isValidAddress(walletAddress) || !isValidAddress(destination)) {
      return res.status(400).json({ error: 'walletAddress and destination must be valid bitcoin addresses' });
    }
    try {
      const built = await buildUnsignedPsbt(
        { walletAddress, destination, amountSats, feeRateSatVb },
        { getUtxos, getPrevout, getTxHex },
      );
      logEvent('psbt.prepare', { walletAddress: walletAddress.trim(), amountSats, feeSats: built.feeSats });
      return res.json(built);
    } catch (e) {
      return res.status(e.status || 502).json({ error: e.message });
    }
  });

  // --- POST /v1/btc/psbt/validate ------------------------------------------
  router.post('/v1/btc/psbt/validate', keyGuard, (req, res) => {
    const { psbt, expected } = req.body || {};
    if (typeof psbt !== 'string' || !psbt || typeof expected !== 'object' || !expected) {
      return res.status(400).json({ valid: false, verdict: 'REJECT', reasons: ['body must include psbt (base64) and expected'] });
    }
    const r = validatePsbt(psbt, expected);
    logEvent('psbt.validate', { valid: r.valid, verdict: r.verdict });
    return res.json(r);
  });

  // --- POST /v1/btc/receipt -------------------------------------------------
  router.post('/v1/btc/receipt', keyGuard, (req, res) => {
    const { txid, ...meta } = req.body || {};
    if (typeof txid !== 'string' || !/^[0-9a-fA-F]{64}$/.test(txid)) {
      return res.status(400).json({ error: 'txid must be 64 hex characters' });
    }
    const rec = {
      txid: txid.toLowerCase(),
      recordedAt: new Date().toISOString(),
      meta: sanitizeMeta(meta),
    };
    receipts.push(rec);
    logEvent('receipt', { txid: rec.txid });
    try {
      fs.appendFileSync(RECEIPT_LOG, JSON.stringify(rec) + '\n');
    } catch (e) { /* file log is best-effort */ }
    return res.json({ recorded: true, txid: rec.txid });
  });

  // --- GET /events ---------------------------------------------------------
  // Audit log: newest first. Query ?limit=N (default 50, max 200).
  // Entries never contain message text, signatures, or PSBTs.
  router.get('/events', (req, res) => {
    const limit = parseInt(req.query.limit, 10);
    const evts = getEvents(limit);
    return res.json({ count: evts.length, events: evts });
  });

  // --- POST /v1/btc/bip322/verify ------------------------------------------
  // Genuine BIP-322 "simple" verification for segwit addresses (P2WPKH,
  // P2SH-P2WPKH, single-key P2TR), via the bip322-js verifier: tagged message
  // hash ("BIP0322-signed-message"), virtual toSpend/toSign reconstruction,
  // and witness/script verification against the claimed address's
  // scriptPubKey. Accepts the "smp"-prefixed form (BIP-322 v2.0.0) and the
  // unprefixed backward-compat form. "ful"/"pof" (full/proof-of-funds) are
  // explicitly rejected — the verifier library only implements "simple".
  // P2WSH is NOT supported by the verifier library (degrades to valid:false,
  // never a 500). A 65-byte decoded payload is a legacy BIP-137 compact
  // signature, not a BIP-322 witness stack: it is verified down the BIP-137
  // path in strict mode and reported with scheme "bip137-legacy".
  // P2PKH (1...) addresses keep using the legacy /verify-ownership endpoint.
  router.post('/v1/btc/bip322/verify', keyGuard, (req, res) => {
    const { address, message, signature } = req.body || {};
    if (!isValidAddress(address) || typeof message !== 'string' ||
        typeof signature !== 'string' || !signature) {
      return res.status(400).json({ valid: false, reason: 'body must include address, message (string, may be empty), and signature' });
    }
    if (message.length > 8192 || signature.length > 65536 || address.length > 128) {
      return res.status(400).json({ valid: false, reason: 'input too long' });
    }
    const addr = address.trim();
    if (addr[0] === '1') {
      return res.json({
        valid: false,
        address: addr,
        reason: 'P2PKH (1...) addresses use the legacy /verify-ownership endpoint; BIP-322 is for segwit addresses',
      });
    }
    // BIP-322 v2.0.0 prefixes the base64 signature with the variant used.
    // "smp" (simple) is routed to the verifier; "ful"/"pof" (full /
    // proof-of-funds) are not implemented by the verifier library and are
    // rejected with an explicit reason. No prefix = pre-finalization
    // backward-compat form, assumed "simple".
    let sig = signature.trim();
    let scheme = 'bip322';
    const prefix = sig.slice(0, 3);
    if (prefix === 'smp') {
      sig = sig.slice(3);
    } else if (prefix === 'ful' || prefix === 'pof') {
      return res.json({
        valid: false,
        address: addr,
        scheme,
        reason: `'${prefix}' (full/proof-of-funds) signatures are not supported; simple ('smp') only`,
      });
    }
    // A 65-byte decoded payload is a legacy BIP-137 compact signature, not a
    // BIP-322 witness stack. Label the scheme honestly instead of calling it
    // BIP-322. (Buffer.from with 'base64' is lenient and never throws.)
    if (Buffer.from(sig, 'base64').length === 65) scheme = 'bip137-legacy';
    let valid = false;
    try {
      // strict mode: the signature must match this exact address type.
      valid = Bip322Verifier.verifySignature(addr, message, sig, true) === true;
    } catch (e) {
      return res.json({ valid: false, address: addr, scheme, reason: 'unverifiable signature' });
    }
    logEvent('bip322.verify', { address: addr, valid });
    return res.json({ valid, address: addr, scheme });
  });

  return router;
}

// Test hooks (in-memory stores; not exposed over HTTP)
export const _stores = { sessions, signerChallenges, ownershipChallenges, receipts, events };
export const _ttls = { SESSION_TTL_MS, SIGNER_CHALLENGE_TTL_MS, OWNERSHIP_CHALLENGE_TTL_MS };
