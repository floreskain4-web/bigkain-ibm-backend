import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function hash160(bytes) {
  return ripemd160(sha256(bytes));
}

function varint(n) {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, (n >> 8) & 0xff);
  const b = new Uint8Array(9); b[0] = 0xfe;
  new DataView(b.buffer).setUint32(1, n, true);
  return b;
}

function magicHash(message) {
  const prefix = new TextEncoder().encode("\x18Bitcoin Signed Message:\n");
  const msg = new TextEncoder().encode(message);
  const pre = new Uint8Array(prefix.length + varint(msg.length).length + msg.length);
  pre.set(prefix, 0);
  pre.set(varint(msg.length), prefix.length);
  pre.set(msg, prefix.length + varint(msg.length).length);
  return sha256(sha256(pre));
}

function addressFromRecovered(pubRecBytes, compressed) {
  // noble v2 recoverPublicKey returns 33-byte compressed pubkey bytes
  const pub = compressed
    ? pubRecBytes
    : secp256k1.Point.fromBytes(pubRecBytes).toBytes(false);
  const h = hash160(pub);
  const payload = new Uint8Array(21); payload[0] = 0x00; payload.set(h, 1);
  const chk = sha256(sha256(payload)).slice(0, 4);
  const full = new Uint8Array(25); full.set(payload, 0); full.set(chk, 21);
  let n = 0n;
  for (const b of full) n = (n << 8n) + BigInt(b);
  let s = "";
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  let lead = 0;
  for (const b of full) { if (b === 0) lead++; else break; }
  return "1".repeat(lead) + s;
}

/**
 * Verify a standard Bitcoin signed message.
 * @returns {{valid:boolean, recoveredAddress:string|null, reason?:string}}
 */
export function verifyMessage(address, message, signatureB64) {
  try {
    const sigBytes = Uint8Array.from(Buffer.from(signatureB64, "base64"));
    if (sigBytes.length !== 65) return { valid: false, recoveredAddress: null, reason: "signature must decode to 65 bytes" };
    const header = sigBytes[0];
    if (header < 27 || header > 34) return { valid: false, recoveredAddress: null, reason: "bad header byte" };
    const compressed = header >= 31;
    const recid = (header - 27) & 3;
    // noble v2 'recovered' format: [recoveryByte, ...64-byte compact sig]
    const rec65 = new Uint8Array(65);
    rec65[0] = recid;
    rec65.set(sigBytes.slice(1), 1);
    const hash = magicHash(message);
    const pubRecBytes = secp256k1.recoverPublicKey(rec65, hash, { prehash: false });
    const recovered = addressFromRecovered(pubRecBytes, compressed);
    return { valid: recovered === address, recoveredAddress: recovered };
  } catch (e) {
    return { valid: false, recoveredAddress: null, reason: e.message };
  }
}
