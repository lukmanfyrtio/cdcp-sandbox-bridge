import { createHash, generateKeyPairSync } from "crypto";
import { describe, expect, it } from "vitest";
import { concat, hexToBytes } from "../src/hex";
import { caKeyTableFromList, emptyCaKeyTable, performOda } from "../src/oda";
import { parseTlv } from "../src/tlv";

// TLV builder with proper BER long-form length encoding — unlike emv.test.ts's fixtures, this
// suite's certificates/signatures are 64-128 bytes, well past the 127-byte short-form limit.
function tlv(tagHex: string, value: Uint8Array): Uint8Array {
  let lengthBytes: Uint8Array;
  if (value.length < 0x80) {
    lengthBytes = Uint8Array.of(value.length);
  } else {
    const bytes: number[] = [];
    let n = value.length;
    while (n > 0) {
      bytes.unshift(n & 0xff);
      n >>= 8;
    }
    lengthBytes = concat(Uint8Array.of(0x80 | bytes.length), Uint8Array.from(bytes));
  }
  return concat(hexToBytes(tagHex), lengthBytes, value);
}

function jwkFieldToBigInt(b64url: string): bigint {
  const buf = Buffer.from(b64url, "base64url");
  let n = 0n;
  for (const byte of buf) n = (n << 8n) | BigInt(byte);
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

/** Real RSA keypair via Node's crypto, with raw (n, d, e) exposed for the EMV-style raw signing this
 * test needs — EMV's ISO 9796-2 message recovery scheme, not PKCS1/OAEP, so Node's own sign/verify
 * APIs (which always apply standard padding) can't be reused here. */
function generateRawRsaKeypair(modulusLengthBits: number) {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: modulusLengthBits, publicExponent: 65537 });
  const pub = publicKey.export({ format: "jwk" }) as { n: string; e: string };
  const priv = privateKey.export({ format: "jwk" }) as { n: string; d: string };
  const modulusBytes = modulusLengthBits / 8;
  return {
    modulus: bigIntToBytes(jwkFieldToBigInt(pub.n), modulusBytes),
    exponent: hexToBytes("010001"), // 65537, 3 bytes — matches the public exponent requested above
    n: jwkFieldToBigInt(pub.n),
    d: jwkFieldToBigInt(priv.d),
    modulusBytes,
  };
}

/** EMV/ISO 9796-2 raw signing: sig = plaintext^d mod n, encoded to the modulus byte length. */
function rawSign(plaintext: Uint8Array, n: bigint, d: bigint, modulusBytes: number): Uint8Array {
  let m = 0n;
  for (const byte of plaintext) m = (m << 8n) | BigInt(byte);
  return bigIntToBytes(modPow(m, d, n), modulusBytes);
}

describe("performOda (SDA)", () => {
  const ca = generateRawRsaKeypair(1024); // NCA = 128 bytes
  const issuer = generateRawRsaKeypair(512); // NI = 64 bytes, comfortably <= NCA-36 (92) — no remainder needed
  const aidHex = "A0000000031010"; // Visa
  const rid = "A000000003";
  const capkIndex = 1;

  // Build the Issuer Public Key Certificate plaintext (EMV Book 2 Table 7), NCA=128 bytes total.
  const leftmostLength = ca.modulusBytes - 36; // 92
  const pkOrLeftmost = concat(issuer.modulus, new Uint8Array(leftmostLength - issuer.modulusBytes).fill(0xbb));
  const issuerCertFixedFields = concat(
    Uint8Array.of(0x02), // format
    hexToBytes("12345678"), // issuer identifier (arbitrary)
    hexToBytes("1231"), // cert expiration MMYY (arbitrary, not validated by performOda)
    hexToBytes("000001"), // cert serial (arbitrary)
    Uint8Array.of(0x01), // hash algorithm indicator (SHA-1)
    Uint8Array.of(0x01), // issuer PK algorithm indicator (RSA)
    Uint8Array.of(issuer.modulusBytes), // issuer PK length (NI)
    Uint8Array.of(issuer.exponent.length), // issuer PK exponent length
    pkOrLeftmost
  );
  const issuerCertHash = new Uint8Array(createHash("sha1").update(concat(issuerCertFixedFields, issuer.exponent)).digest());
  const issuerCertPlaintext = concat(Uint8Array.of(0x6a), issuerCertFixedFields, issuerCertHash, Uint8Array.of(0xbc));
  const issuerCert = rawSign(issuerCertPlaintext, ca.n, ca.d, ca.modulusBytes);

  const aipSdaSupported = Uint8Array.of(0x80, 0x00);
  const record70 = tlv("70", tlv("57", hexToBytes("4111111111111111D28121010000000000FF")));
  const rawRecords = [{ sfi: 1, record: 1, raw: record70 }];
  const staticDataToAuthenticate = concat(aipSdaSupported, record70);

  // Build the Signed Static Application Data plaintext (EMV Book 2 §5.4), NI=64 bytes total.
  const pad = new Uint8Array(issuer.modulusBytes - 26).fill(0xbb);
  const ssadFixedFields = concat(
    Uint8Array.of(0x03), // format
    Uint8Array.of(0x01), // hash algorithm indicator
    hexToBytes("0000"), // data authentication code (arbitrary)
    pad
  );
  const ssadHash = new Uint8Array(createHash("sha1").update(concat(ssadFixedFields, staticDataToAuthenticate)).digest());
  const signedStaticData = rawSign(
    concat(Uint8Array.of(0x6a), ssadFixedFields, ssadHash, Uint8Array.of(0xbc)),
    issuer.n,
    issuer.d,
    issuer.modulusBytes
  );

  const record = tlv(
    "70",
    concat(
      tlv("8F", Uint8Array.of(capkIndex)),
      tlv("90", issuerCert),
      tlv("9F32", issuer.exponent),
      tlv("93", signedStaticData)
    )
  );
  const recordsTlv = parseTlv(record);
  const aflEntries = [{ sfi: 1, firstRecord: 1, lastRecord: 1, offlineAuthRecordCount: 1 }];
  const caKeys = caKeyTableFromList([{ rid, index: capkIndex, modulus: ca.modulus, exponent: ca.exponent }]);

  it("verifies a correctly signed card as valid SDA", () => {
    const result = performOda({ aip: aipSdaSupported, aflEntries, rawRecords, recordsTlv, aidHex, caKeys });
    expect(result).toEqual({ performed: true, method: "SDA", valid: true });
  });

  it("flags tampered signed static data as invalid, not as a crash or false pass", () => {
    const tamperedSsad = signedStaticData.slice();
    tamperedSsad[10] ^= 0xff;
    const tamperedRecord = tlv(
      "70",
      concat(
        tlv("8F", Uint8Array.of(capkIndex)),
        tlv("90", issuerCert),
        tlv("9F32", issuer.exponent),
        tlv("93", tamperedSsad)
      )
    );
    const result = performOda({
      aip: aipSdaSupported,
      aflEntries,
      rawRecords,
      recordsTlv: parseTlv(tamperedRecord),
      aidHex,
      caKeys,
    });
    expect(result.performed).toBe(true);
    expect(result.valid).toBe(false);
  });

  it("flags tampered record data (not just the signature itself) as invalid", () => {
    const tamperedRaw = record70.slice();
    tamperedRaw[tamperedRaw.length - 1] ^= 0xff; // corrupt the Track2 data the signature covers
    const result = performOda({
      aip: aipSdaSupported,
      aflEntries,
      rawRecords: [{ sfi: 1, record: 1, raw: tamperedRaw }],
      recordsTlv,
      aidHex,
      caKeys,
    });
    expect(result.performed).toBe(true);
    expect(result.valid).toBe(false);
  });

  it("reports not-performed (not a false pass) when no CAPK is on file for the RID/index", () => {
    const result = performOda({ aip: aipSdaSupported, aflEntries, rawRecords, recordsTlv, aidHex, caKeys: emptyCaKeyTable });
    expect(result.performed).toBe(false);
    expect(result.reason).toMatch(/no CAPK/i);
  });

  it("skips ODA when the AIP says the card doesn't offer SDA", () => {
    const result = performOda({
      aip: Uint8Array.of(0x00, 0x00),
      aflEntries,
      rawRecords,
      recordsTlv,
      aidHex,
      caKeys,
    });
    expect(result.performed).toBe(false);
    expect(result.reason).toMatch(/SDA/);
  });

  it("reports not-performed when the card's records are missing SDA tags despite AIP claiming support", () => {
    const bareRecord = parseTlv(tlv("70", tlv("57", hexToBytes("4111111111111111D28121010000000000FF"))));
    const result = performOda({ aip: aipSdaSupported, aflEntries, rawRecords, recordsTlv: bareRecord, aidHex, caKeys });
    expect(result.performed).toBe(false);
    expect(result.reason).toMatch(/missing SDA tags/);
  });
});
