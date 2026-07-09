// Generates a self-issued, sandbox-only CAPK (Certification Authority Public Key) — same field
// names as a real EMV kernel SDK's `capks.format.json` (CAPKName/RID/CAPKIndex/CAPKModulus/
// CAPKExponent/CAPKChecksum/CAPKExpirationDate), but every key is generated fresh right here.
//
// Never copy a real scheme's CAPK (Visa/Mastercard/Amex/JCB/GPN, or one a licensed vendor SDK
// ships) into a project that isn't that vendor's certified, licensed deployment — even if it's
// just numbers sitting in a JSON file you technically have read access to. This script exists so
// you never need to: it mints an RSA keypair under a RID reserved for local/proprietary use
// (ISO/IEC 7816-5 — RIDs starting "F0" are never assigned to a registered card scheme, so this can
// never collide with or be mistaken for a real one), which only ever verifies a card YOU personalize
// yourself with the matching private key (e.g. a JavaCard EMV applet under your own control).
//
// Run: npx tsx src/tools/generateTestCapk.ts
// Writes: test-fixtures/sandbox-capks.format.json   (public — safe to commit, drives performOda via
//                                                     caKeyTableFromJson)
//         test-fixtures/sandbox-ca-private-key.json  (private — needed later only to sign a test
//                                                     card's Issuer Public Key Certificate; keep
//                                                     out of anything that isn't your own test rig)
import { createHash, generateKeyPairSync } from "crypto";
import { mkdirSync, writeFileSync } from "fs";
import { join } from "path";

const RID = "F0000000AA"; // proprietary/test RID — not a real registered scheme RID (all start "A0")
const CAPK_INDEX = "01";
const MODULUS_BITS = 1024;

function jwkFieldToBigInt(b64url: string): bigint {
  const buf = Buffer.from(b64url, "base64url");
  let n = 0n;
  for (const byte of buf) n = (n << 8n) | BigInt(byte);
  return n;
}

function bigIntToHex(n: bigint, byteLength: number): string {
  return n.toString(16).toUpperCase().padStart(byteLength * 2, "0");
}

function main() {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: MODULUS_BITS, publicExponent: 65537 });
  const pub = publicKey.export({ format: "jwk" }) as { n: string; e: string };
  const priv = privateKey.export({ format: "jwk" });

  const modulusHex = bigIntToHex(jwkFieldToBigInt(pub.n), MODULUS_BITS / 8);
  const exponentHex = "010001"; // 65537, matches generateKeyPairSync's publicExponent above

  // EMV Book 2 Annex B2: CAPK Check Sum = SHA-1(RID || Index || Modulus || Exponent).
  const checksum = createHash("sha1")
    .update(Buffer.from(RID + CAPK_INDEX + modulusHex + exponentHex, "hex"))
    .digest("hex")
    .toUpperCase();

  const publicTable = [
    {
      CAPKName: "CDCP Sandbox Test CA (self-issued, not a real scheme)",
      RID,
      CAPKIndex: CAPK_INDEX,
      CAPKModulus: modulusHex,
      CAPKExponent: exponentHex,
      CAPKChecksum: checksum,
      CAPKExpirationDate: "20991231",
    },
  ];

  const outDir = join(__dirname, "..", "..", "test-fixtures");
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, "sandbox-capks.format.json"), JSON.stringify(publicTable, null, 2) + "\n");
  writeFileSync(
    join(outDir, "sandbox-ca-private-key.json"),
    JSON.stringify(
      {
        warning:
          "TEST-ONLY — generated for this sandbox, never a real scheme's key. Needed only to sign an " +
          "Issuer Public Key Certificate (tag 90) for a card you personalize yourself under RID " +
          RID +
          ". Do not treat as a secret worth protecting beyond 'don't publish', since it secures nothing real.",
        RID,
        CAPKIndex: CAPK_INDEX,
        privateKeyJwk: priv,
      },
      null,
      2
    ) + "\n"
  );

  console.log(`Wrote ${outDir}/sandbox-capks.format.json (public — safe to commit)`);
  console.log(`Wrote ${outDir}/sandbox-ca-private-key.json (only needed for signing a test card later)`);
  console.log(`RID=${RID} CAPKIndex=${CAPK_INDEX} CAPKChecksum=${checksum}`);
}

main();
