---
name: bitcoin-unsigned-psbt
description: Safety workflow for Bitcoin ownership checks and unsigned PSBT preparation in this repository. Use for wallet, transaction, UTXO, PSBT, signer, challenge, or transaction-approval changes and reviews.
---
# Bitcoin safety boundary

**Never request, import, generate, store, echo, or use private keys, seed phrases, mnemonics, WIFs, xprvs, or other signing secrets.** Do not sign, spend, finalize signed transactions, or broadcast. Only prepare an **unsigned PSBT** for funds controlled by the user; the user reviews and signs with their own hardware wallet, then broadcasts themselves. Never make an external production/funds call. Use synthetic public fixtures only; no real funds.

- Before work, inspect the relevant `signer.js` path, its tests, and README contract. Check addresses, networks, input ownership, exact destination/amount, change, and fee policy; fail closed on malformed or ambiguous transactions.
- Never submit a signed PSBT to backend endpoints or use signer/finalizer/extraction APIs, even if available in dependencies. Existing signed-PSBT validation/signing-oriented behavior is legacy/out of scope; do not execute, expand, or silently rewrite it. Flag conflicts for separate authorization.
- Tests must use synthetic data and stubs. If a test can reach a network, wallet, key store, node, or production endpoint, do not run it.
- A PSBT is a transaction proposal, not approval. Explain material outputs/fees to the user and require their independent hardware-wallet review/signature and self-broadcast.
