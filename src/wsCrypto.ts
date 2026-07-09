// AES-256-GCM helpers for encrypting `card_read` payloads sent over the WebSocket to the web app.
// Without this, the phone-bridge -> browser hop would carry PAN/Track2/Field-55 as plain JSON —
// fine on localhost, not fine the moment `bridgeUrl` points at anything routed over a real network
// (see NfcReaderPanel.tsx's wss://ws.lukman.site default). Wire format: ciphertext with the 16-byte
// GCM auth tag appended, which is exactly what the browser's SubtleCrypto AES-GCM decrypt expects
// (see cdcp-sandbox-web/src/crypto/wsCrypto.ts) — no reshaping needed on either side.
import { createCipheriv, createDecipheriv, randomBytes } from "crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const KEY_LENGTH = 32;
const TAG_LENGTH = 16;

export interface EncryptedPayload {
  iv: string;
  data: string;
}

export function encryptJson(key: Buffer, value: unknown): EncryptedPayload {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const plaintext = Buffer.from(JSON.stringify(value), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: iv.toString("hex"), data: Buffer.concat([ciphertext, tag]).toString("hex") };
}

export function decryptJson<T = unknown>(key: Buffer, payload: EncryptedPayload): T {
  const iv = Buffer.from(payload.iv, "hex");
  const blob = Buffer.from(payload.data, "hex");
  if (blob.length < TAG_LENGTH) throw new Error("encrypted payload shorter than the GCM auth tag — truncated or corrupt");
  const ciphertext = blob.subarray(0, blob.length - TAG_LENGTH);
  const tag = blob.subarray(blob.length - TAG_LENGTH);
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]); // throws if tampered
  return JSON.parse(plaintext.toString("utf8")) as T;
}

/**
 * Loads the shared key from WS_ENCRYPT_KEY (hex, 64 chars) if set — so it stays stable across
 * restarts once you've pasted it into the web app once — otherwise mints a fresh one for this
 * session only and prints it so you can paste it into the web app's "WS Encryption Key" field.
 */
export function loadOrGenerateKey(envValue: string | undefined, log: (msg: string) => void = console.log): Buffer {
  if (envValue) {
    const key = Buffer.from(envValue, "hex");
    if (key.length !== KEY_LENGTH) {
      throw new Error(`WS_ENCRYPT_KEY must be ${KEY_LENGTH} bytes (${KEY_LENGTH * 2} hex chars), got ${key.length} byte(s)`);
    }
    return key;
  }
  const key = randomBytes(KEY_LENGTH);
  const hex = key.toString("hex");
  log("No WS_ENCRYPT_KEY set — generated an ephemeral key for this session only.");
  log(`Paste this into the web app's "WS Encryption Key" field:  ${hex}`);
  log(`(Or set WS_ENCRYPT_KEY=${hex} in the environment to keep using it across restarts.)`);
  return key;
}
