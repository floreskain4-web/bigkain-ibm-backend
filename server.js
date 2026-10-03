import express from "express";
import { verifyMessage } from "./verify.js";

const app = express();
app.use(express.json({ limit: "32kb" }));

const PORT = process.env.PORT || 8080;

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

app.listen(PORT, "0.0.0.0", () => {
  console.log(`BigKain backend listening on ${PORT}`);
});
