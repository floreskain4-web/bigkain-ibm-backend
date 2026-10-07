/**
 * bigkain-ibm-backend — non-custodial Bitcoin verification service.
 *
 * What it does:
 *   - Proves address ownership via Bitcoin message signatures (no key material here)
 *   - Reads address balances / UTXOs from mempool.space (read-only)
 *   - Optionally proxies signed holding attestations via the Insumer API
 *     (only when INSUMER_API_KEY is configured)
 *   - WebView Backend Signer: signing sessions, challenges, unsigned PSBT
 *     preparation and PSBT policy validation (see signer.js)
 *
 * What it NEVER does:
 *   - Hold private keys, seed phrases, or any signing material
 *   - Sign transactions or broadcast them (it builds UNSIGNED PSBTs only;
 *     there is deliberately no broadcast endpoint)
 */

import express from "express";
import helmet from "helmet";
import { fileURLToPath } from "node:url";
import { verifyMessage } from "./verify.js";
import { createSignerRouter, verifyOwnershipMessage } from "./signer.js";
import { createEtfFlowRouter } from "./market.js";

const app = express();
app.use(helmet());
app.use(express.json({ limit: "100kb" }));

const PORT = process.env.PORT || 8080;
const MEMPOOL_API = process.env.MEMPOOL_API || "https://mempool.space/api";
const INSUMER_API = "https://api.insumermodel.com/v1";

const OWNERSHIP_ADDRESS =
  "1Ay8vMC7R1UbyCCZRVULMV7iQpHSAbguJP";

// Non-custodial: this backend never receives, stores, or handles private keys.
// It only verifies signed messages against a claimed address.
let lastProof = { status: "UNPROVEN", address: OWNERSHIP_ADDRESS, verified_at: null };

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "bigkain-backend",
    network: "bitcoin-mainnet",
    ownership_address: OWNERSHIP_ADDRESS,
    ownership_proof: lastProof.status,
    private_keys_received: false
  });
});

app.post("/verify", (req, res) => {
  const { address, message, signature } = req.body || {};
  if (typeof address !== "string" || typeof message !== "string" || typeof signature !== "string") {
    return res.status(400).json({ valid: false, reason: "address, message and signature are required strings" });
  }
  if (message.length > 8192 || signature.length > 256 || address.length > 128) {
    return res.status(400).json({ valid: false, reason: "input too long" });
  }
  const r = verifyMessage(address.trim(), message, signature.trim());
  if (r.valid && address.trim() === OWNERSHIP_ADDRESS) {
    lastProof = { status: "PROVEN", address: OWNERSHIP_ADDRESS, verified_at: new Date().toISOString() };
  }
  res.json({ valid: r.valid, recovered_address: r.recoveredAddress, ...(r.reason ? { reason: r.reason } : {}) });
});

// Loose Bitcoin address check: P2PKH (1...), P2SH (3...), bech32 (bc1q...), bech32m (bc1p...)
const ADDR_RE = /^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$/;

function isValidAddress(addr) {
  return typeof addr === "string" && ADDR_RE.test(addr.trim());
}

async function mempool(path) {
  const res = await fetch(`${MEMPOOL_API}${path}`);
  if (!res.ok) {
    const err = new Error(`mempool.space responded ${res.status}`);
    err.status = res.status === 404 ? 404 : 502;
    throw err;
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// POST /verify-ownership — { address, message, signature } -> { valid }
// Verifies a Bitcoin "signmessage" style signature against the address.
// Supports base58 addresses (P2PKH 1..., P2SH 3...). Bech32/bc1 addresses
// use a different signature scheme (BIP-322) and are reported unsupported.
// ---------------------------------------------------------------------------
app.post("/verify-ownership", (req, res) => {
  const { address, message, signature } = req.body || {};
  if (!isValidAddress(address) || typeof message !== "string" || !message ||
      typeof signature !== "string" || !signature) {
    return res.status(400).json({
      valid: false,
      reason: "body must include address, message, and signature",
    });
  }
  const addr = address.trim();
  if (addr.startsWith("bc1")) {
    return res.json({
      valid: false,
      address: addr,
      reason: "bech32 (bc1...) signatures use BIP-322 and are not supported by this endpoint; use a base58 (1.../3...) address",
    });
  }
  let valid = false;
  let reason;
  try {
    const r = verifyOwnershipMessage(addr, message, signature);
    valid = r.valid;
    reason = r.reason;
  } catch (e) {
    return res.json({ valid: false, address: addr, reason: e.message });
  }
  return res.json({ valid, address: addr, ...(reason ? { reason } : {}) });
});

// ---------------------------------------------------------------------------
// GET /address/:address — confirmed balance + tx count (mempool.space)
// ---------------------------------------------------------------------------
app.get("/address/:address", async (req, res) => {
  const addr = req.params.address;
  if (!isValidAddress(addr)) {
    return res.status(400).json({ error: "invalid bitcoin address" });
  }
  try {
    const info = await mempool(`/address/${addr}`);
    const funded = info.chain_stats.funded_txo_sum || 0;
    const spent = info.chain_stats.spent_txo_sum || 0;
    res.json({
      address: addr,
      balanceSats: funded - spent,
      fundedSats: funded,
      spentSats: spent,
      txCount: info.chain_stats.tx_count || 0,
      mempool: {
        fundedSats: info.mempool_stats.funded_txo_sum || 0,
        spentSats: info.mempool_stats.spent_txo_sum || 0,
        txCount: info.mempool_stats.tx_count || 0,
      },
    });
  } catch (e) {
    res.status(e.status || 502).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// GET /address/:address/utxos — spendable outputs (mempool.space)
// ---------------------------------------------------------------------------
app.get("/address/:address/utxos", async (req, res) => {
  const addr = req.params.address;
  if (!isValidAddress(addr)) {
    return res.status(400).json({ error: "invalid bitcoin address" });
  }
  try {
    const utxos = await mempool(`/address/${addr}/utxo`);
    res.json({
      address: addr,
      count: utxos.length,
      totalSats: utxos.reduce((s, u) => s + (u.value || 0), 0),
      utxos,
    });
  } catch (e) {
    res.status(e.status || 502).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// POST /attest — signed holding attestation via the Insumer API (optional).
// Requires INSUMER_API_KEY env. Body: { bitcoinWallet, conditions }.
// Without a key this endpoint is disabled (501) — the /address endpoints
// above remain the keyless verification path.
// ---------------------------------------------------------------------------
app.post("/attest", async (req, res) => {
  const apiKey = process.env.INSUMER_API_KEY;
  if (!apiKey) {
    return res.status(501).json({
      error: "Insumer attestation is not configured (INSUMER_API_KEY not set)",
    });
  }
  const { bitcoinWallet, conditions, format } = req.body || {};
  if (!isValidAddress(bitcoinWallet) || !Array.isArray(conditions) || !conditions.length) {
    return res.status(400).json({ error: "body must include bitcoinWallet and a non-empty conditions array" });
  }
  try {
    const upstream = await fetch(`${INSUMER_API}/attest`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
      body: JSON.stringify({ bitcoinWallet, conditions, ...(format ? { format } : {}) }),
    });
    const data = await upstream.json();
    res.status(upstream.status).json(data);
  } catch (e) {
    res.status(502).json({ error: `insumer upstream error: ${e.message}` });
  }
});

// WebView Backend Signer endpoints (/v1/...) — non-custodial policy layer.
// The router gets the mempool.space helper for UTXO/tx lookups.
app.use(createSignerRouter({ mempool, mempoolBase: MEMPOOL_API }));
app.use(createEtfFlowRouter());

app.use((req, res) => res.status(404).json({ error: "not found" }));

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`BigKain backend listening on ${PORT}`);
  });
}

export default app;
