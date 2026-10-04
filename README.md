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
| POST | `/verify-ownership` | `{ address, message, signature }` | `{ valid, address }` — legacy signmessage verification, base58 addresses only (bc1… uses BIP-322: reported unsupported) |
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

All `POST /v1/*` endpoints reject with 4xx (never stack traces) on bad input
and refuse any key-like material. JSON bodies are limited to 100kb; helmet
headers are on.

## Intended flow (WebView Backend Signer)

1. `POST /v1/signer/session` → session (public info only)
2. `POST /v1/signer/challenge` → challenge the wallet signs **locally, on the
   user's device, after explicit approval**
3. `POST /v1/btc/ownership/verify` (or `/v1/btc/psbt/validate`) → backend
   verifies and enforces policy; the private key never crosses the wire

## Layout

- `server.js` — Express app (health, verify, ownership, address, attest), mounts the signer router
- `signer.js` — sessions/challenges, PSBT build + validate, receipt log
- `verify.js` — recovery-based Bitcoin message verifier (@noble/curves)
- `test/server.test.js`, `test/signer.test.js` — `npm test` (38 tests)
