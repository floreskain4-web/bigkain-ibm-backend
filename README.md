# bigkain-ibm-backend

Non-custodial Bitcoin verification and policy service for BigKain.

**Live dashboard:** [BigKain system status and ETF-flow dashboard](https://floreskain4-web.github.io/bigkain-ibm-backend/).

**What it does:** proves address ownership via Bitcoin message signatures
(two endpoints: recovery-based `/verify` and legacy `/verify-ownership`),
reads balances/UTXOs from mempool.space, issues signing sessions and
challenges, builds **unsigned** PSBTs, validates transaction policy, and
verifies transaction-specific wallet approval.

**What it NEVER does:** hold private keys, seed phrases, or any signing
material, sign transactions, or broadcast them. The connected wallet signs and
submits only after its own confirmation. Requests containing key-like fields
(seed, mnemonic, xprv, privateKey, WIF values) are rejected outright on all
`/v1/*` endpoints.

## Live system status

<section id="bk-live-status" aria-label="Live BigKain system status">
  <p data-status-summary role="status" aria-live="polite">Loading live system checks…</p>
  <div class="bk-status-grid">
    <div class="bk-status-card" data-check="backend" role="group" aria-label="Backend API status">
      <div class="bk-status-heading"><span class="bk-status-dot" data-light data-state="checking" aria-hidden="true"></span><strong>Backend API</strong><span data-value>Checking</span></div>
      <p data-detail>Checking the live health endpoint.</p>
    </div>
    <div class="bk-status-card" data-check="network" role="group" aria-label="Bitcoin network status">
      <div class="bk-status-heading"><span class="bk-status-dot" data-light data-state="checking" aria-hidden="true"></span><strong>Network</strong><span data-value>Checking</span></div>
      <p data-detail>Reading the network reported by the backend.</p>
    </div>
    <div class="bk-status-card" data-check="key-boundary" role="group" aria-label="Private key boundary status">
      <div class="bk-status-heading"><span class="bk-status-dot" data-light data-state="checking" aria-hidden="true"></span><strong>Key boundary</strong><span data-value>Checking</span></div>
      <p data-detail>Reading the backend's public key-material status.</p>
    </div>
    <div class="bk-status-card" data-check="etf" role="group" aria-label="ETF market data API status">
      <div class="bk-status-heading"><span class="bk-status-dot" data-light data-state="checking" aria-hidden="true"></span><strong>ETF data API</strong><span data-value>Checking</span></div>
      <p data-detail>Checking the read-only market-data endpoint.</p>
    </div>
  </div>
  <p class="bk-status-footer"><span data-checked-time>Last checked: —</span> · Refreshes automatically every 60 seconds. The flow signal is market data, not service health.</p>
</section>

<style>
#bk-live-status{margin:1.5rem 0;padding:1.1rem 1.2rem;border:1px solid #d0d7de;border-radius:12px;background:#f6f8fa;color:#1f2328}
#bk-live-status [data-status-summary]{margin:0 0 .8rem;font-weight:600}
.bk-status-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:.75rem}
.bk-status-card{padding:.8rem .9rem;border:1px solid #d0d7de;border-radius:10px;background:#fff}
.bk-status-heading{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
.bk-status-heading strong{margin-right:auto}
.bk-status-heading [data-value]{font-size:.9rem;font-weight:600}
.bk-status-card p{margin:.45rem 0 0;color:#57606a;font-size:.9rem}
.bk-status-dot{display:inline-block;width:.7rem;height:.7rem;flex:0 0 .7rem;border-radius:50%;background:#8c959f}
.bk-status-dot[data-state="online"]{background:#1a7f37;box-shadow:0 0 0 3px #1a7f3720}
.bk-status-dot[data-state="warning"]{background:#bf8700;box-shadow:0 0 0 3px #bf870020}
.bk-status-dot[data-state="offline"]{background:#cf222e;box-shadow:0 0 0 3px #cf222e20}
.bk-status-footer{margin:.8rem 0 0;color:#57606a;font-size:.85rem}
</style>

<script src="/bigkain-ibm-backend/status.js" defer></script>

## Run

```bash
npm install
npm start            # PORT env, default 8080
npm test             # node --test test/*.test.js
```

Optional: `INSUMER_API_KEY` enables `POST /attest`; `MEMPOOL_API` overrides the
mempool.space base URL. Transaction-bound approvals require the sensitive
`BIGKAIN_TRANSACTION_DATABASE_URL` Neon connection string; without it, those
routes fail closed with 503. `BIGKAIN_WALLET_ORIGIN` sets the exact browser
origin allowed to call wallet-preparation/approval routes (defaults to the
BigKain Vercel app). The backend has no transaction-broadcast endpoint: the
connected wallet remains responsible for final signing and submission.

Transaction approval currently supports only single-key P2PKH, P2WPKH, and
key-path P2TR inputs. P2SH, P2WSH, and Taproot script-path/tree policies are
rejected rather than estimating their spending requirements. Every input must
use SIGHASH_ALL (or Taproot SIGHASH_DEFAULT), and total fees are capped at
100,000 satoshis. The commitment binds the entire unsigned PSBT, including its
signing metadata. The app must keep that PSBT unchanged and the wallet must
independently review the final signing request; a server receipt cannot force
an external wallet to obey its policy.

## Endpoints

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/health` | — | `{ ok: true, service: 'bigkain-backend', network: 'bitcoin-mainnet', ownership_address, ownership_proof, private_keys_received: false }` |
| POST | `/verify` | `{ address, message, signature }` | `{ valid, recovered_address }` — recovery-based signature verification only; does not independently change gated ownership state |
| POST | `/verify-ownership` | `{ address, message, signature }` | `{ valid, address }` — legacy signmessage verification, base58 addresses only (bc1… segwit addresses use `POST /v1/btc/bip322/verify`) |
| GET | `/address/:address` | — | balance, funded/spent sats, tx counts (chain + mempool) |
| GET | `/address/:address/utxos` | — | spendable outputs from mempool.space |
| POST | `/attest` | `{ bitcoinWallet, conditions }` | 501 unless `INSUMER_API_KEY` is set |
| POST | `/v1/signer/session` | `{ walletAddress, purpose }` | `{ sessionId: 'bk_sess_…', walletAddress, purpose, status: 'PENDING_APPROVAL', createdAt, expiresAt }` — 10 min TTL, public info only |
| POST | `/v1/signer/challenge` | `{ sessionId }` | `{ challengeId: 'bk_ch_…', nonce, purpose, walletAddress, expiresAt }` — 5 min TTL |
| POST | `/v1/btc/ownership/challenge` | `{ address, psbt? }` | `{ challengeId, address, message, expiresAt, transactionCommitment? }` — 10 min normally; 5 min when bound to the exact unsigned PSBT, with confirmed inputs, fee, every output, and an explicit approval statement spelled out in the message. Transaction-bound mode requires the durable Neon store. |
| POST | `/v1/btc/ownership/verify` | `{ address, message, signature, challengeId? }` | `{ valid, address, challengeId? }` — when `challengeId` is given, the challenge must exist, be unexpired and unused, and the message/address must match; it is then marked used (replay protection). Uses legacy signed-message verification for P2PKH, and BIP-322 simple verification for supported SegWit addresses, including P2SH-P2WPKH. |
| POST | `/v1/btc/psbt/prepare` | `{ walletAddress, destination, amountSats, feeRateSatVb }` | `{ psbt (base64, unsigned), inputs, outputs, feeSats, changeSats }` — selects confirmed UTXOs (smallest-first), RBF signaled, change back to the wallet, dust change folded into the fee |
| POST | `/v1/btc/psbt/validate` | `{ psbt (base64), expected: { destination, amountSats, feeRateSatVb?, walletAddress } }` | `{ valid, verdict: 'SAFE_HOLD' \| 'REJECT', reasons[] }` — checks all inputs signed, inputs belong to `walletAddress`, exactly one output pays `destination`+`amountSats`, all other outputs are change to the wallet, fee within sane bounds, mainnet only |
| POST | `/v1/btc/transaction/approve` | `{ psbt, expected, challengeId, message, signature, explicitApproval: { approved: true, transactionCommitment, walletAddress, destination, amountSats } }` | `{ approved, approvalId, approvedAt, expiresAt, summary, walletAction }` — requires an unsigned PSBT, policy-valid transaction, confirmed prevout data, and a fresh wallet signature over the exact transaction-bound approval message. The one-use challenge expires after 5 min. The connected wallet performs final signing/submission. Returns 503 if the durable Neon store is unavailable. |
| POST | `/v1/btc/receipt` | `{ txid, ...meta }` | `{ recorded: true, txid }` — appends to an in-memory log and `receipts.jsonl` |
| POST | `/v1/btc/bip322/verify` | `{ address, message, signature }` | `{ valid, address, scheme }` — verifies BIP-322 simple signatures for P2WPKH, P2SH-P2WPKH, and single-key P2TR; accepts `smp`-prefixed signatures and the unprefixed compatibility form. Unprefixed BIP-137 compact signatures are labeled `bip137-legacy`. Full (`ful`), proof-of-funds (`pof`), P2WSH, and Taproot script-path signatures are not supported; P2PKH (1…) continues to use the legacy verifier. |
| GET | `/v1/btc/market/etf-flow` | — | Farside daily and five-session BTC spot ETF net flows in USD millions, session breadth, and a `GREEN` / `YELLOW` / `RED` signal |
| GET | `/events` | `?limit=N` (default 50, max 200) | `{ count, events: [{ ts, type, detail }] }` — newest first; audit log of verification/PSBT/receipt activity; never contains message text, signatures, or PSBTs |

All `POST /v1/*` endpoints reject with 4xx (never stack traces) on bad input
and refuse any key-like material. JSON bodies are limited to 100kb; helmet
headers are on.

`GET /v1/btc/market/etf-flow` is read-only and fetches Farside Investors' [Bitcoin ETF all-data table](https://farside.co.uk/bitcoin-etf-flow-all-data/) through Jina Reader because direct server-side requests receive a Cloudflare challenge. The response identifies Farside as the data source and Jina Reader as the retrieval intermediary. It uses the published `Total` column and the five latest rows with at least one reported fund value, excluding holidays or not-yet-reported rows. `dailyNetFlowUsdM` and `fiveSessionNetFlowUsdM` are USD millions; positive and negative session counts cover that same five-session window. `GREEN` requires positive five-session flow and more positive than negative sessions; `RED` requires negative flow and more negative than positive sessions; otherwise the result is `YELLOW`. It does not initiate or authorize wallet actions.

## Intended flow (WebView Backend Signer)

1. `POST /v1/btc/psbt/prepare` → unsigned PSBT; the app displays destination,
   amount, fee, and change before requesting a signature.
2. `POST /v1/btc/ownership/challenge` with `{ address, psbt }` → fresh
   transaction commitment and a message listing confirmed inputs, fee, and
   every output. The user reviews the message and signs it in the wallet.
3. `POST /v1/btc/transaction/approve` → policy and proof verification; the
   server atomically consumes the challenge in Neon and returns an approval
   receipt. The database stores only public transaction metadata and a hash of
   the message—not the raw message, signature, PSBT, or any key material.
4. The app asks the connected wallet to sign and submit the transaction. The
   wallet owns the final confirmation; BigKain's backend never signs or
   broadcasts.

## Layout

- `server.js` — Express app (health, verify, ownership, address, attest), mounts signer and market routers
- `signer.js` — sessions/challenges, PSBT build + validate, approval gate, receipt log
- `transaction-store.js` — one-use in-memory test store and atomic Neon challenge store
- `migrations/002_btc_approval_challenges.sql` — additive durable challenge table and runtime-role grants
- `market.js` — read-only Farside ETF flow retrieval, parsing, and signal calculation
- `verify.js` — recovery-based Bitcoin message verifier (@noble/curves)
- `test/*.test.js` — `npm test`, covering ETF parsing, signal behavior, endpoint and GET-only rules, transaction approval, and replay protection.
