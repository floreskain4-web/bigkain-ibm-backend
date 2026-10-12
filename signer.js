/**
 * signer.js — "WebView Backend Signer" endpoint set for bigkain-ibm-backend.
 *
 * Non-custodial by construction:
 *   - The backend verifies signatures and enforces policy. It NEVER receives,
 *     stores, or logs seeds, mnemonics, xprvs, or private keys.
 *   - It builds unsigned PSBTs and verifies transaction-specific approval.
 *     The connected wallet performs all signing and broadcasting.
 *
 * Ordinary sessions/ownership proofs live in memory and expire quickly.
 * Transaction-specific challenges use a durable store when configured and
 * are atomically single-use across server instances.
 */

import { Router } from 'express';
import { createHash, randomBytes } from 'node:crypto';
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
const TRANSACTION_APPROVAL_TTL_MS = 5 * 60 * 1000;
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
// BIP-322 verification core, shared by the gated /v1/btc/ownership/verify
// endpoint (segwit addresses) and the stateless /v1/btc/bip322/verify
// endpoint. Routes by signature prefix per BIP-322 v2.0.0: "smp" (simple) is
// verified; "ful"/"pof" (full/proof-of-funds) are rejected — the verifier
// library only implements "simple". No prefix = pre-finalization
// backward-compat form, assumed simple. A 65-byte decoded payload is a
// legacy BIP-137 compact signature, not a BIP-322 witness stack, and is
// labeled honestly as bip137-legacy. P2WSH degrades to valid:false (library
// limitation), never a 500. Returns { valid, scheme, reason? }.
// ---------------------------------------------------------------------------
export function verifyBip322Signature(addr, message, signature) {
  const a = (addr || '').trim();
  if (a[0] === '1') {
    return {
      valid: false,
      scheme: 'bip322',
      reason: 'P2PKH (1...) addresses use the legacy /verify-ownership endpoint; BIP-322 is for segwit addresses',
    };
  }
  let sig = (signature || '').trim();
  let scheme = 'bip322';
  const prefix = sig.slice(0, 3);
  if (prefix === 'smp') {
    sig = sig.slice(3);
  } else if (prefix === 'ful' || prefix === 'pof') {
    return {
      valid: false,
      scheme,
      reason: `'${prefix}' (full/proof-of-funds) signatures are not supported; simple ('smp') only`,
    };
  }
  // Buffer.from with 'base64' is lenient and never throws.
  if (Buffer.from(sig, 'base64').length === 65) scheme = 'bip137-legacy';
  try {
    // strict mode: the signature must match this exact address type.
    const valid = Bip322Verifier.verifySignature(a, message, sig, true) === true;
    return { valid, scheme };
  } catch (e) {
    return { valid: false, scheme, reason: 'unverifiable signature' };
  }
}

// ---------------------------------------------------------------------------
// Ownership-signature verification routed by address type — check 6 of the
// ownership gate:
//   P2PKH/P2SH (1.../3...) -> legacy bitcoinjs-message ("Bitcoin Signed Message")
//   segwit (bc1...)         -> genuine BIP-322 verification
// Returns { valid, scheme: 'legacy' | 'bip322' | 'bip137-legacy', reason? }.
// ---------------------------------------------------------------------------
export function verifyOwnershipSignature(addr, message, signature) {
  const a = (addr || '').trim();
  if (a[0] === '1' || a[0] === '3') {
    const r = verifyOwnershipMessage(a, message, signature);
    return { valid: r.valid, scheme: 'legacy', ...(r.reason ? { reason: r.reason } : {}) };
  }
  return verifyBip322Signature(a, message, signature);
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
export function validatePsbt(psbtBase64, expected, options = {}) {
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

  // 1. Existing validation requires signed inputs. Approval validates the
  // unsigned transaction template before the wallet signs it.
  if (options.requireSignatures !== false) {
    const unsigned = [];
    psbt.data.inputs.forEach((inp, i) => {
      const sigs = inp.partialSig || [];
      if (!sigs.length && !inp.finalScriptSig && !inp.finalScriptWitness) unsigned.push(i);
    });
    if (unsigned.length) reasons.push(`unsigned inputs: ${unsigned.join(',')}`);
  }

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
        const expectedTxid = Buffer.from(psbt.txInputs[i].hash).reverse().toString('hex');
        if (prevTx.getId() !== expectedTxid) {
          reasons.push(`input ${i}: non-witness transaction id mismatch`);
        }
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

// Canonical commitment to the unsigned transaction skeleton. ScriptSig and
// witness data are intentionally excluded so a later locally signed
// transaction can be matched to the approved inputs, sequences and outputs.
function transactionTemplateFromPsbt(psbt) {
  return {
    version: psbt.version,
    locktime: psbt.locktime,
    inputs: psbt.txInputs.map((input) => ({
      txid: Buffer.from(input.hash).reverse().toString('hex'),
      vout: input.index,
      sequence: input.sequence == null ? 0xffffffff : input.sequence,
    })),
    outputs: psbt.txOutputs.map((output) => ({
      scriptHex: Buffer.from(output.script).toString('hex'),
      value: Number(output.value),
    })),
  };
}

function commitmentForTemplate(template) {
  return createHash('sha256').update(JSON.stringify(template)).digest('hex');
}

function hashApprovalMessage(message) {
  return createHash('sha256').update(message, 'utf8').digest('hex');
}

export function getPsbtTransactionCommitment(psbtBase64) {
  if (typeof psbtBase64 !== 'string' || !psbtBase64) {
    throw Object.assign(new Error('psbt must be a non-empty base64 string'), { status: 400 });
  }
  let psbt;
  try {
    psbt = Psbt.fromBase64(psbtBase64);
  } catch {
    throw Object.assign(new Error('invalid PSBT encoding'), { status: 400 });
  }
  return commitmentForTemplate(transactionTemplateFromPsbt(psbt));
}

// ---------------------------------------------------------------------------
// Ephemeral stores for ordinary sessions and non-transaction ownership proofs.
// Transaction-specific approval challenges use deps.transactionStore, which
// must be shared/durable in production serverless deployments.
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
// Router factory. deps: { mempool(path), mempoolBase, transactionStore? }.
// The wallet signs and broadcasts locally; the backend never handles keys or
// relays payments.
// ---------------------------------------------------------------------------
export function createSignerRouter(deps) {
  const router = Router();
  const transactionStore = deps.transactionStore || null;

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
    return { scriptHex: o.scriptpubkey, value: o.value, confirmed: !!(tx.status && tx.status.confirmed) };
  }

  async function getTxHex(txid) {
    const res = await fetch(`${deps.mempoolBase || 'https://mempool.space/api'}/tx/${txid}/hex`);
    if (!res.ok) throw Object.assign(new Error(`mempool.space responded ${res.status}`), { status: 502 });
    return (await res.text()).trim();
  }

  function psbtHasAnySignature(psbt) {
    return psbt.data.inputs.some((input) =>
      (input.partialSig || []).length > 0 ||
      Boolean(input.tapKeySig) ||
      (input.tapScriptSig || []).length > 0 ||
      Boolean(input.finalScriptSig && input.finalScriptSig.length) ||
      Boolean(input.finalScriptWitness && input.finalScriptWitness.length));
  }

  async function verifyApprovalPrevouts(psbt) {
    let inputSum = 0;
    for (let i = 0; i < psbt.txInputs.length; i += 1) {
      const input = psbt.txInputs[i];
      const txid = Buffer.from(input.hash).reverse().toString('hex');
      const actual = await getPrevout(txid, input.index);
      if (actual.confirmed !== true) {
        throw Object.assign(new Error(`input ${i}: previous output is not confirmed`), { status: 400 });
      }
      const actualScript = actual.scriptHex.toLowerCase();
      const candidates = [];
      const psbtInput = psbt.data.inputs[i];
      if (psbtInput.witnessUtxo) {
        candidates.push({
          scriptHex: Buffer.from(psbtInput.witnessUtxo.script).toString('hex').toLowerCase(),
          value: Number(psbtInput.witnessUtxo.value),
        });
      }
      if (psbtInput.nonWitnessUtxo) {
        const prevTx = Transaction.fromBuffer(psbtInput.nonWitnessUtxo);
        if (prevTx.getId() !== txid) {
          throw Object.assign(new Error(`input ${i}: non-witness transaction id mismatch`), { status: 400 });
        }
        const prevout = prevTx.outs[input.index];
        if (!prevout) {
          throw Object.assign(new Error(`input ${i}: previous output not found`), { status: 400 });
        }
        candidates.push({ scriptHex: Buffer.from(prevout.script).toString('hex').toLowerCase(), value: Number(prevout.value) });
      }
      if (!candidates.length || candidates.some((candidate) =>
        candidate.scriptHex !== actualScript || candidate.value !== Number(actual.value))) {
        throw Object.assign(new Error(`input ${i}: PSBT UTXO data does not match the confirmed previous output`), { status: 400 });
      }
      inputSum += Number(actual.value);
    }
    return inputSum;
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
  router.post('/v1/btc/ownership/challenge', keyGuard, async (req, res) => {
    const { address, psbt } = req.body || {};
    if (!isValidAddress(address)) {
      return res.status(400).json({ error: 'address must be a valid bitcoin address' });
    }
    if (psbt !== undefined && !transactionStore) {
      return res.status(503).json({ error: 'durable transaction approval storage is not configured' });
    }
    let transactionCommitment;
    let transactionOutputLines = [];
    let transactionFeeSats;
    let transactionInputCount;
    if (psbt !== undefined) {
      if (typeof psbt !== 'string' || !psbt || psbt.length > 90000) {
        return res.status(400).json({ error: 'psbt must be a non-empty base64 string (max 90000 chars)' });
      }
      try {
        const parsed = Psbt.fromBase64(psbt);
        if (psbtHasAnySignature(parsed)) {
          return res.status(400).json({ error: 'approval challenge requires an unsigned PSBT' });
        }
        const template = transactionTemplateFromPsbt(parsed);
        if (template.inputs.length < 1 || template.inputs.length > 100 ||
            template.outputs.length < 1 || template.outputs.length > 128) {
          return res.status(400).json({ error: 'approval challenges support 1-100 inputs and 1-128 outputs' });
        }
        transactionCommitment = commitmentForTemplate(template);
        transactionInputCount = template.inputs.length;
        const inputSum = await verifyApprovalPrevouts(parsed);
        const outputSum = template.outputs.reduce((sum, output) => sum + output.value, 0);
        transactionFeeSats = inputSum - outputSum;
        if (!Number.isSafeInteger(transactionFeeSats) || transactionFeeSats <= 0) {
          return res.status(400).json({ error: 'transaction fee must be a positive integer number of satoshis' });
        }
        transactionOutputLines = template.outputs.map((output, index) => {
          const outputAddress = addressFromScript(Buffer.from(output.scriptHex, 'hex'));
          const walletOutput = outputAddress === address.trim() ? ' (wallet/change)' : '';
          return `Output ${index + 1}: ${outputAddress} — ${output.value} sats${walletOutput}`;
        });
      } catch (e) {
        return res.status(e.status || 400).json({ error: e.status ? e.message : 'PSBT contains an output that cannot be shown as a mainnet address' });
      }
    }
    const now = Date.now();
    const ttl = transactionCommitment ? Math.min(OWNERSHIP_CHALLENGE_TTL_MS, TRANSACTION_APPROVAL_TTL_MS) : OWNERSHIP_CHALLENGE_TTL_MS;
    const expiresAt = new Date(now + ttl).toISOString();
    const nonce = randomBytes(16).toString('hex');
    const message = [
      transactionCommitment ? 'BIGKAIN TRANSACTION-SPECIFIC APPROVAL' : 'BIGKAIN OWNERSHIP PROOF',
      `Address: ${address.trim()}`,
      `Nonce: ${nonce}`,
      `Issued: ${new Date(now).toISOString()}`,
      `Expires: ${expiresAt}`,
      ...(transactionCommitment ? [
        `Transaction commitment: ${transactionCommitment}`,
        `Input count: ${transactionInputCount}`,
        `Transaction fee: ${transactionFeeSats} sats`,
        'Exact outputs:',
        ...transactionOutputLines,
        'By signing, I explicitly approve signing and submitting this exact transaction through my connected wallet after reviewing the destinations, amounts, and fee. This message does not itself spend bitcoin.',
      ] : [
        'Sign this message with the private key for the address above. Nothing moves; nothing broadcasts.',
      ]),
    ].join('\n');
    if (message.length > 8192) {
      return res.status(400).json({ error: 'transaction approval message is too long to review safely' });
    }
    const challengeId = 'bk_ch_' + randomBytes(16).toString('hex');
    const challenge = {
      challengeId,
      address: address.trim(),
      message,
      nonce,
      transactionCommitment: transactionCommitment || null,
      expiresAt,
      used: false,
    };
    if (transactionCommitment) {
      try {
        await transactionStore.createChallenge({
          challengeId,
          walletAddress: address.trim(),
          messageHash: hashApprovalMessage(message),
          transactionCommitment,
          expiresAt,
        });
      } catch {
        return res.status(503).json({ error: 'durable transaction approval storage is unavailable' });
      }
    } else {
      ownershipChallenges.set(challengeId, challenge);
    }
    return res.json({
      challengeId,
      address: address.trim(),
      message,
      expiresAt,
      ...(transactionCommitment ? { transactionCommitment } : {}),
    });
  });

  // --- POST /v1/btc/ownership/verify -------------------------------------
  // The ownership gate: RED -> challenge -> wallet signs the exact challenge
  // message -> this endpoint checks all six conditions -> GREEN.
  //
  //   1. address matches the challenge
  //   2. exact message matches the challenge (byte-for-byte)
  //   3. fresh nonce matches — the nonce is unique per challenge and embedded
  //      in the message, so check 2 implies check 3; asserted explicitly below
  //   4. challenge has not expired (getChallenge sweeps expired entries)
  //   5. challenge/nonce has not already been used — single-use. The challenge
  //      is burned once the binding checks (1-3) pass, before signature
  //      verification, so each challenge allows exactly one signature
  //      attempt. Binding failures do NOT burn, so a mistyped submission can
  //      be retried with a fresh attempt.
  //   6. signature validates for the address type (verifyOwnershipSignature):
  //      legacy path for P2PKH/P2SH, genuine BIP-322 for segwit addresses.
  //
  // Without a challengeId the endpoint still verifies a bare signature
  // (legacy behavior), but the response is marked gated:false — it is NOT a
  // gated ownership proof.
  router.post('/v1/btc/ownership/verify', keyGuard, (req, res) => {
    const { address, message, signature, challengeId } = req.body || {};
    if (!isValidAddress(address) || typeof message !== 'string' || !message ||
        typeof signature !== 'string' || !signature) {
      return res.status(400).json({ valid: false, reason: 'body must include address, message, and signature' });
    }
    if (message.length > 8192 || signature.length > 65536 || address.length > 128) {
      return res.status(400).json({ valid: false, reason: 'input too long' });
    }
    const addr = address.trim();
    let gated = false;
    if (challengeId != null) {
      if (typeof challengeId !== 'string' || !challengeId) {
        return res.status(400).json({ valid: false, reason: 'challengeId must be a string' });
      }
      const c = getChallenge(ownershipChallenges, challengeId);
      // 4. unknown or expired challenge
      if (!c) {
        return res.status(400).json({ valid: false, reason: 'unknown or expired challenge' });
      }
      // 5. replay protection
      if (c.used) {
        logEvent('ownership.verify', { address: addr, valid: false, challengeId });
        return res.json({ valid: false, address: addr, challengeId, reason: 'challenge already used (replay rejected)' });
      }
      // 1. address must match the challenge
      if (c.address !== addr) {
        logEvent('ownership.verify', { address: addr, valid: false, challengeId });
        return res.json({ valid: false, address: addr, challengeId, reason: 'address does not match the issued challenge' });
      }
      // 2. exact message must match the challenge
      if (c.message !== message) {
        logEvent('ownership.verify', { address: addr, valid: false, challengeId });
        return res.json({ valid: false, address: addr, challengeId, reason: 'message does not match the issued challenge' });
      }
      // 3. fresh nonce must be present in the message
      if (!message.includes(c.nonce)) {
        logEvent('ownership.verify', { address: addr, valid: false, challengeId });
        return res.json({ valid: false, address: addr, challengeId, reason: 'challenge nonce missing from message' });
      }
      c.used = true; // burn on first attempt: one challenge, one shot
      gated = true;
    }
    // 6. signature / script validation, routed by address type
    const r = verifyOwnershipSignature(addr, message, signature);
    logEvent('ownership.verify', { address: addr, valid: r.valid, gated, scheme: r.scheme, ...(challengeId ? { challengeId } : {}) });
    return res.json({
      valid: r.valid,
      address: addr,
      scheme: r.scheme,
      gated,
      ...(r.reason ? { reason: r.reason } : {}),
      ...(challengeId ? { challengeId } : {}),
    });
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

  // --- POST /v1/btc/transaction/approve -----------------------------------
  // A fresh, transaction-bound ownership challenge must be signed by the
  // wallet. The backend validates the approval but never signs or broadcasts.
  router.post('/v1/btc/transaction/approve', keyGuard, async (req, res) => {
    if (!transactionStore) {
      return res.status(503).json({ error: 'durable transaction approval storage is not configured' });
    }
    const { psbt: psbtBase64, expected, challengeId, message, signature, explicitApproval } = req.body || {};
    if (typeof psbtBase64 !== 'string' || !psbtBase64 || psbtBase64.length > 90000 ||
        !expected || typeof expected !== 'object' || Array.isArray(expected) ||
        typeof challengeId !== 'string' || !/^bk_ch_[0-9a-f]{32}$/.test(challengeId) ||
        typeof message !== 'string' || !message || message.length > 8192 ||
        typeof signature !== 'string' || !signature || signature.length > 65536) {
      return res.status(400).json({ error: 'body must include psbt, expected, challengeId, message, and signature' });
    }
    if (!explicitApproval || typeof explicitApproval !== 'object' || Array.isArray(explicitApproval) ||
        explicitApproval.approved !== true ||
        typeof explicitApproval.transactionCommitment !== 'string' ||
        !isValidAddress(expected.destination) || !isValidAddress(expected.walletAddress) ||
        explicitApproval.destination !== expected.destination.trim() ||
        explicitApproval.walletAddress !== expected.walletAddress.trim() ||
        explicitApproval.amountSats !== expected.amountSats) {
      return res.status(400).json({ error: 'explicitApproval must confirm approved:true, the exact commitment, wallet, destination, and amount' });
    }

    let psbt;
    try {
      psbt = Psbt.fromBase64(psbtBase64);
    } catch {
      return res.status(400).json({ error: 'invalid PSBT encoding' });
    }
    if (psbtHasAnySignature(psbt)) {
      return res.status(400).json({ error: 'approval requires an unsigned PSBT; sign only after approval' });
    }
    const template = transactionTemplateFromPsbt(psbt);
    if (template.inputs.length < 1 || template.inputs.length > 100 ||
        template.outputs.length < 1 || template.outputs.length > 128) {
      return res.status(400).json({ error: 'approval supports 1-100 inputs and 1-128 outputs' });
    }
    const transactionCommitment = commitmentForTemplate(template);
    if (explicitApproval.transactionCommitment !== transactionCommitment) {
      return res.status(400).json({ error: 'explicitApproval transactionCommitment does not match this PSBT' });
    }

    const policy = validatePsbt(psbtBase64, expected, { requireSignatures: false });
    if (!policy.valid) {
      logEvent('transaction.approve.rejected', { reason: 'policy' });
      return res.status(422).json({ valid: false, verdict: 'REJECT', reasons: policy.reasons });
    }

    let challenge;
    try {
      challenge = await transactionStore.getChallenge(challengeId);
    } catch {
      return res.status(503).json({ error: 'durable transaction approval storage is unavailable' });
    }
    if (!challenge) return res.status(400).json({ error: 'ownership challenge not found' });
    if (challenge.consumedAt) return res.status(409).json({ error: 'ownership challenge already used (replay rejected)' });
    if (Date.parse(challenge.expiresAt) <= Date.now()) {
      return res.status(400).json({ error: 'ownership challenge expired' });
    }
    if (challenge.walletAddress !== expected.walletAddress.trim() ||
        challenge.transactionCommitment !== transactionCommitment ||
        challenge.messageHash !== hashApprovalMessage(message)) {
      return res.status(400).json({ error: 'fresh ownership challenge does not match this wallet and exact transaction' });
    }

    let inputSum;
    try {
      inputSum = await verifyApprovalPrevouts(psbt);
    } catch (e) {
      return res.status(e.status || 502).json({ error: e.message || 'could not verify transaction inputs' });
    }

    // The database's conditional UPDATE atomically burns this challenge across
    // Vercel instances. A bad signature also consumes the challenge.
    let consumed;
    try {
      consumed = await transactionStore.consumeChallenge(challengeId);
    } catch {
      return res.status(503).json({ error: 'durable transaction approval storage is unavailable' });
    }
    if (!consumed) {
      return res.status(409).json({ error: 'ownership challenge expired or already used (replay rejected)' });
    }

    const proof = verifyOwnershipSignature(challenge.walletAddress, message, signature);
    if (!proof.valid) {
      logEvent('transaction.approve.rejected', { reason: 'ownership', scheme: proof.scheme });
      return res.status(403).json({ error: 'fresh ownership proof is invalid', scheme: proof.scheme });
    }

    const now = Date.now();
    const approvalId = 'bk_txapp_' + randomBytes(16).toString('hex');
    let approval;
    try {
      approval = await transactionStore.markApproved(challengeId, approvalId);
    } catch {
      return res.status(503).json({ error: 'durable transaction approval storage is unavailable' });
    }
    if (!approval) {
      return res.status(409).json({ error: 'ownership challenge was consumed before approval could be recorded' });
    }
    const outputSum = template.outputs.reduce((sum, output) => sum + output.value, 0);
    const summary = {
      transactionCommitment,
      walletAddress: expected.walletAddress.trim(),
      destination: expected.destination.trim(),
      amountSats: expected.amountSats,
      feeSats: inputSum - outputSum,
      inputCount: template.inputs.length,
      outputCount: template.outputs.length,
    };

    const expiresAt = challenge.expiresAt;
    logEvent('transaction.approve', { approvalId, amountSats: summary.amountSats, destination: summary.destination });
    return res.json({
      approved: true,
      approvalId,
      approvedAt: approval.approvedAt || new Date(now).toISOString(),
      expiresAt,
      summary,
      walletAction: 'Sign and submit the transaction with the connected wallet; the backend never signs or broadcasts.',
    });
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
  // Stateless BIP-322 verification for segwit addresses (P2WPKH,
  // P2SH-P2WPKH, single-key P2TR). No challenge binding here — for the gated
  // ownership proof, use POST /v1/btc/ownership/verify with a challengeId.
  // Shares its crypto core with the gate via verifyBip322Signature.
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
    const r = verifyBip322Signature(addr, message, signature);
    logEvent('bip322.verify', { address: addr, valid: r.valid });
    return res.json({ valid: r.valid, address: addr, scheme: r.scheme, ...(r.reason ? { reason: r.reason } : {}) });
  });

  return router;
}

// Test hooks (in-memory stores; not exposed over HTTP)
export const _stores = { sessions, signerChallenges, ownershipChallenges, receipts, events };
export const _ttls = { SESSION_TTL_MS, SIGNER_CHALLENGE_TTL_MS, OWNERSHIP_CHALLENGE_TTL_MS, TRANSACTION_APPROVAL_TTL_MS };
