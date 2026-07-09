// Offline Data Authentication (SDA/DDA/CDA) — EMV Book 2 §5 / Book 3 §10.3, Annex C5.
//
// This verifies signatures the CARD gives us using RSA public-key "recovery" (ISO/IEC 9796-2 —
// a message-recovery scheme, NOT PKCS1 encryption padding), rooted at a Certification Authority
// Public Key (CAPK) per scheme/RID. The math here is public domain; the CAPK is not: each scheme
// (Visa, Mastercard, ...) only issues its real CAPKs to entities with an EMVCo Level 2 kernel
// certification agreement. Without the real key for a card's RID+index, this module reports
// "no key, can't verify" (see emptyCaKeyTable) rather than fabricating a result — a personal
// sandbox has no legal way to obtain a scheme's production CAPK. To actually exercise this end to
// end, populate a CaKeyTable with either a scheme-provided *test* CAPK (their test/certification
// program) or your own self-issued RID+CAPK on a card you personalize yourself (e.g. a JavaCard
// EMV applet under your own control) — never a real bank card.
//
// Only SDA is implemented. DDA and CDA also need an ICC (per-card) key certificate plus a dynamic
// signature — DDA requires sending an extra INTERNAL AUTHENTICATE command this bridge doesn't send
// yet, and CDA's hash input has scheme-specific nuances beyond what's implemented here. Guessing
// either would risk exactly the "false confidence" this module exists to avoid, so both remain
// unimplemented (performOda simply never sets method to "DDA"/"CDA") rather than approximated.
import { createHash } from "crypto";
import { AflEntry } from "./apdu";
import { bytesToHex, concat } from "./hex";
import { findTag, TlvNode } from "./tlv";

export interface CaPublicKey {
  rid: string; // 5-byte RID, hex (10 hex chars), e.g. "A000000003" for Visa
  index: number; // tag 8F value (0-255)
  modulus: Uint8Array;
  exponent: Uint8Array;
}

export interface CaKeyTable {
  find(rid: string, index: number): CaPublicKey | null;
}

export const emptyCaKeyTable: CaKeyTable = { find: () => null };

/** Convenience constructor for a small fixed set of keys (e.g. a self-issued test CAPK). */
export function caKeyTableFromList(keys: CaPublicKey[]): CaKeyTable {
  return {
    find(rid, index) {
      return keys.find((k) => k.rid.toUpperCase() === rid.toUpperCase() && k.index === index) ?? null;
    },
  };
}

export interface OdaResult {
  performed: boolean;
  method?: "SDA" | "DDA" | "CDA";
  /** Signature check outcome — only meaningful when performed is true. */
  valid?: boolean;
  /** Why ODA wasn't performed or failed, for logs — not itself fed into TVR. */
  reason?: string;
}

// ---- RSA public-key "recovery" primitive (EMV Book 2 §5.2 / ISO 9796-2) ----

function bytesToBigInt(b: Uint8Array): bigint {
  let n = 0n;
  for (const byte of b) n = (n << 8n) | BigInt(byte);
  return n;
}

function bigIntToBytes(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let n = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus === 1n) return 0n;
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    e >>= 1n;
    b = (b * b) % modulus;
  }
  return result;
}

/**
 * Raw RSA "encrypt with the public key" over data the same length as the modulus — this recovers
 * whatever the corresponding private key signed (no OAEP/PKCS1 padding involved, per EMV/ISO 9796-2).
 * Returns null for shapes that can't possibly be a valid signature under this key (wrong length, or
 * the numeric value doesn't reduce mod n) — that's a normal "not verifiable with this key", not a bug.
 */
function recoverWithPublicKey(signature: Uint8Array, modulus: Uint8Array, exponent: Uint8Array): Uint8Array | null {
  if (signature.length !== modulus.length || signature.length === 0) return null;
  const n = bytesToBigInt(modulus);
  const sig = bytesToBigInt(signature);
  if (sig >= n) return null;
  const recovered = modPow(sig, bytesToBigInt(exponent), n);
  return bigIntToBytes(recovered, modulus.length);
}

function sha1(...parts: Uint8Array[]): Uint8Array {
  const h = createHash("sha1");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

const CERT_HEADER = 0x6a;
const CERT_TRAILER = 0xbc;
const ISSUER_CERT_FORMAT = 0x02;
const SIGNED_STATIC_DATA_FORMAT = 0x03;

export interface RecoveredPublicKey {
  modulus: Uint8Array;
  exponent: Uint8Array;
}

/**
 * Recover the Issuer Public Key from its CA-signed certificate (tag 90), per EMV Book 2 Table 7.
 * Fixed layout, independent of key size: header(1) format(1) issuerId(4) expDate(2) serial(3)
 * hashAlgo(1) pkAlgo(1) pkLength(1) pkExpLength(1) [pk-or-leftmost-digits] hash(20) trailer(1) —
 * the bracketed field is (CA modulus length − 36) bytes, whatever that comes out to.
 */
function recoverIssuerPublicKey(
  certificate: Uint8Array,
  caModulus: Uint8Array,
  caExponent: Uint8Array,
  remainder: Uint8Array | undefined,
  exponentValue: Uint8Array
): RecoveredPublicKey | null {
  const recovered = recoverWithPublicKey(certificate, caModulus, caExponent);
  if (!recovered || recovered.length < 36) return null;
  if (recovered[0] !== CERT_HEADER || recovered[recovered.length - 1] !== CERT_TRAILER) return null;
  if (recovered[1] !== ISSUER_CERT_FORMAT) return null;

  const pkLength = recovered[13]; // NI
  const leftmostLength = recovered.length - 36;
  const pkOrLeftmost = recovered.slice(15, 15 + leftmostLength);
  const hash = recovered.slice(15 + leftmostLength, 15 + leftmostLength + 20);

  const hashInput = concat(recovered.slice(1, 15 + leftmostLength), remainder ?? new Uint8Array(0), exponentValue);
  if (bytesToHex(sha1(hashInput)) !== bytesToHex(hash)) return null;

  const modulus =
    pkLength <= leftmostLength ? pkOrLeftmost.slice(0, pkLength) : concat(pkOrLeftmost, remainder ?? new Uint8Array(0));
  if (modulus.length !== pkLength) return null; // remainder (tag 92) missing/short — can't trust the key

  return { modulus, exponent: exponentValue };
}

/**
 * Assemble "the data to be authenticated" for SDA (EMV Book 3 §10.3): the AIP, followed by the
 * full record data (including each record's own template tag+length) for every record an AFL entry
 * flags for offline data authentication (its 4th byte, offlineAuthRecordCount — always the *first*
 * N records of that entry's range).
 *
 * Known simplification: skips the rare edge case where a GPO Format-2 (template 77) response record
 * is itself one of the flagged records — that record would need to contribute only its AIP/AFL
 * values, not the full template 77 wrapper, which this bridge doesn't reconstruct.
 */
function buildStaticDataToAuthenticate(
  aip: Uint8Array,
  aflEntries: AflEntry[],
  rawRecords: { sfi: number; record: number; raw: Uint8Array }[]
): Uint8Array {
  const parts: Uint8Array[] = [aip];
  for (const entry of aflEntries) {
    if (entry.offlineAuthRecordCount <= 0) continue;
    const count = Math.min(entry.offlineAuthRecordCount, entry.lastRecord - entry.firstRecord + 1);
    for (let i = 0; i < count; i++) {
      const recNum = entry.firstRecord + i;
      const rec = rawRecords.find((r) => r.sfi === entry.sfi && r.record === recNum);
      if (rec) parts.push(rec.raw);
    }
  }
  return concat(...parts);
}

/**
 * Verify Signed Static Application Data (tag 93) against the recovered Issuer Public Key, per EMV
 * Book 2 §5.4: header(1) format(1) hashAlgo(1) dataAuthCode(2) pad(NI−26, value BB) hash(20)
 * trailer(1) — NI is the Issuer PK modulus length, so pad length varies with key size, not fixed.
 */
function verifySignedStaticData(signedData: Uint8Array, issuerPk: RecoveredPublicKey, staticData: Uint8Array): boolean {
  const recovered = recoverWithPublicKey(signedData, issuerPk.modulus, issuerPk.exponent);
  if (!recovered || recovered.length < 26) return false;
  if (recovered[0] !== CERT_HEADER || recovered[recovered.length - 1] !== CERT_TRAILER) return false;
  if (recovered[1] !== SIGNED_STATIC_DATA_FORMAT) return false;

  const pad = recovered.length - 26;
  const hash = recovered.slice(5 + pad, 5 + pad + 20);
  const hashInput = concat(recovered.slice(1, 5 + pad), staticData);
  return bytesToHex(sha1(hashInput)) === bytesToHex(hash);
}

export interface OdaInput {
  /** AIP as read from GPO (tag 82) — governs whether the card even offers SDA. Null = GPO didn't yield one. */
  aip: Uint8Array | null;
  aflEntries: AflEntry[];
  rawRecords: { sfi: number; record: number; raw: Uint8Array }[];
  /** Parsed record tags (8F/90/92/9F32/93), searched recursively. */
  recordsTlv: TlvNode[];
  /** Full AID hex — only the first 10 hex chars (5-byte RID) are used, to look up the CAPK. */
  aidHex: string;
  caKeys: CaKeyTable;
}

// AIP byte 1, bit 8 (0x80) = SDA supported (EMV Book 3 Table 8).
const AIP_SDA_SUPPORTED = 0x80;

export function performOda(input: OdaInput): OdaResult {
  const { aip, aflEntries, rawRecords, recordsTlv, aidHex, caKeys } = input;
  if (!aip || aip.length < 1) return { performed: false, reason: "no AIP from GPO" };
  if ((aip[0] & AIP_SDA_SUPPORTED) === 0) return { performed: false, reason: "AIP: card does not offer SDA" };

  const capkIndexTag = findTag(recordsTlv, "8F")?.value;
  const issuerCert = findTag(recordsTlv, "90")?.value;
  const issuerExponent = findTag(recordsTlv, "9F32")?.value;
  const signedStaticData = findTag(recordsTlv, "93")?.value;
  if (!capkIndexTag || !issuerCert || !issuerExponent || !signedStaticData) {
    return { performed: false, reason: "card missing SDA tags (8F/90/9F32/93) despite AIP claiming support" };
  }

  const rid = aidHex.slice(0, 10).toUpperCase();
  const caKey = caKeys.find(rid, capkIndexTag[0]);
  if (!caKey) return { performed: false, reason: `no CAPK on file for RID ${rid} index ${capkIndexTag[0].toString(16)}` };

  const issuerRemainder = findTag(recordsTlv, "92")?.value;
  const issuerPk = recoverIssuerPublicKey(issuerCert, caKey.modulus, caKey.exponent, issuerRemainder, issuerExponent);
  if (!issuerPk) return { performed: true, method: "SDA", valid: false, reason: "issuer certificate recovery/hash mismatch" };

  const staticData = buildStaticDataToAuthenticate(aip, aflEntries, rawRecords);
  const valid = verifySignedStaticData(signedStaticData, issuerPk, staticData);
  return { performed: true, method: "SDA", valid };
}
