# bigkain-ibm-backend

Non-custodial Bitcoin verification and policy service for BigKain.

**What it does:** proves address ownership via Bitcoin message signatures
(two endpoints: recovery-based `/verify` and legacy `/verify-ownership`),
reads balances/UTXOs from mempool.space, issues signing sessions and
challenges, builds **unsigned** PSBTs, validates signed PSBTs against policy,
and records transaction receipts.

**What it NEVER does:** hold private keys, seed phrases, or any signing
material. It never signs and never broadcasts. There is deliberately **no
broadcast endpoint**. Requests containing key-like fields (seed, mnemonic,
xprv, privateKey, WIF values) are rejected outright on all `/v1/*` endpoints.

## Run

```bash
npm install
npm start            # PORT env, default 8080
npm test             # node --test test/*.test.js
```

Optional: `INSUMER_API_KEY` enables `POST /attest`. `MEMPOOL_API` overrides
the mempool.space base URL.

## Endpoints

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/health` | — | `{ ok: true, service: 'bigkain-backend', network: 'bitcoin-mainnet', ownership_address, ownership_proof, private_keys_received: false }` |
| POST | `/verify` | `{ address, message, signature }` | `{ valid, recovered_address }` — recovery-based verification (any address type); flips `ownership_proof` to `PROVEN` when the ownership address verifies |
| POST | `/verify-ownership` | `{ address, message, signature }` | `{ valid, address }` — legacy signmessage verification, base58 addresses only (bc1… segwit addresses use `POST /v1/btc/bip322/verify`) |
| GET | `/address/:address` | — | balance, funded/spent sats, tx counts (chain + mempool) |
| GET | `/address/:address/utxos` | — | spendable outputs from mempool.space |
| POST | `/attest` | `{ bitcoinWallet, conditions }` | 501 unless `INSUMER_API_KEY` is set |
| POST | `/v1/signer/session` | `{ walletAddress, purpose }` | `{ sessionId: 'bk_sess_…', walletAddress, purpose, status: 'PENDING_APPROVAL', createdAt, expiresAt }` — 10 min TTL, public info only |
| POST | `/v1/signer/challenge` | `{ sessionId }` | `{ challengeId: 'bk_ch_…', nonce, purpose, walletAddress, expiresAt }` — 5 min TTL |
| POST | `/v1/btc/ownership/challenge` | `{ address }` | `{ challengeId, address, message, expiresAt }` — human-readable challenge text, 10 min TTL |
| POST | `/v1/btc/ownership/verify` | `{ address, message, signature, challengeId? }` | `{ valid, address, challengeId? }` — when `challengeId` is given, the challenge must exist, be unexpired and unused, and the message/address must match; it is then marked used (replay protection) |
| POST | `/v1/btc/psbt/prepare` | `{ walletAddress, destination, amountSats, feeRateSatVb }` | `{ psbt (base64, unsigned), inputs, outputs, feeSats, changeSats }` — selects confirmed UTXOs (smallest-first), RBF signaled, change back to the wallet, dust change folded into the fee |
| POST | `/v1/btc/psbt/validate` | `{ psbt (base64), expected: { destination, amountSats, feeRateSatVb?, walletAddress } }` | `{ valid, verdict: 'SAFE_HOLD' \| 'REJECT', reasons[] }` — checks all inputs signed, inputs belong to `walletAddress`, exactly one output pays `destination`+`amountSats`, all other outputs are change to the wallet, fee within sane bounds, mainnet only |
| POST | `/v1/btc/receipt` | `{ txid, ...meta }` | `{ recorded: true, txid }` — appends to an in-memory log and `receipts.jsonl` |
| POST | `/v1/btc/bip322/verify` | `{ address, message, signature }` | `{ valid, address, scheme: 'bip322' }` — genuine BIP-322 verification for segwit addresses (P2WPKH, P2SH-P2WPKH, P2WSH, single-key P2TR), "simple" and "full" encodings; P2PKH (1…) is routed to `/verify-ownership` |
| GET | `/v1/btc/market/etf-flow` | — | Farside daily and five-session BTC spot ETF net flows in USD millions, session breadth, and a `GREEN` / `YELLOW` / `RED` signal |
| GET | `/events` | `?limit=N` (default 50, max 200) | `{ count, events: [{ ts, type, detail }] }` — newest first; audit log of verification/PSBT/receipt activity; never contains message text, signatures, or PSBTs |

All `POST /v1/*` endpoints reject with 4xx (never stack traces) on bad input
and refuse any key-like material. JSON bodies are limited to 100kb; helmet
headers are on.

`GET /v1/btc/market/etf-flow` is read-only and fetches Farside Investors' [Bitcoin ETF all-data table](https://farside.co.uk/bitcoin-etf-flow-all-data/) through Jina Reader because direct server-side requests receive a Cloudflare challenge. The response identifies Farside as the data source and Jina Reader as the retrieval intermediary. It uses the published `Total` column and the five latest rows with at least one reported fund value, excluding holidays or not-yet-reported rows. `dailyNetFlowUsdM` and `fiveSessionNetFlowUsdM` are USD millions; positive and negative session counts cover that same five-session window. `GREEN` requires positive five-session flow and more positive than negative sessions; `RED` requires negative flow and more negative than positive sessions; otherwise the result is `YELLOW`. It does not initiate or authorize wallet actions.

## Intended flow (WebView Backend Signer)

1. `POST /v1/signer/session` → session (public info only)
2. `POST /v1/signer/challenge` → challenge the wallet signs **locally, on the
   user's device, after explicit approval**
3. `POST /v1/btc/ownership/verify` (or `/v1/btc/psbt/validate`) → backend
   verifies and enforces policy; the private key never crosses the wire

## Layout

- `server.js` — Express app (health, verify, ownership, address, attest), mounts signer and market routers
- `signer.js` — sessions/challenges, PSBT build + validate, receipt log
- `market.js` — read-only Farside ETF flow retrieval, parsing, and signal calculation
- `verify.js` — recovery-based Bitcoin message verifier (@noble/curves)
- `test/*.test.js` — `npm test`, including ETF parser, signal, endpoint, and GET-only tests

## ChatGPT Action integration

The authenticated facade is defined by `openapi-chatgpt-bigkain.yaml` and serves under `/v1/chatgpt/*` on the existing Vercel alias `https://bigkain-ibm-backend.vercel.app`. Configure `BIGKAIN_CHATGPT_API_KEY` as an encrypted Vercel environment variable for each environment that should accept Action requests; never commit the value. Requests use `Authorization: Bearer <key>`.

The facade can read balances, UTXOs, and workflow events; prepare **unsigned** PSBTs; and validate signer-produced PSBTs. It never accepts key material, signs, approves spending, or broadcasts. The existing `signer.js` and `verify.js` are unchanged.

**Ownership-state safeguard:** This integration currently has only process-local challenge state. Ownership challenge and verification routes therefore return `503` by default and in all production/serverless deployments until a durable shared challenge store is implemented. The explicit ephemeral mode is limited to local non-production tests; deployed status reports ownership as `UNAVAILABLE`, never `GREEN`. The existing process-local event log is also instance-scoped and is not a durable audit store.
