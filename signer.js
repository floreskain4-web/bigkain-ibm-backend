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

// TEMP incomplete - will replace with full file
export function createSignerRouter(deps) {
  const router = Router();
  return router;
}
export const _stores = {};
export const _ttls = { SESSION_TTL_MS, SIGNER_CHALLENGE_TTL_MS, OWNERSHIP_CHALLENGE_TTL_MS };
