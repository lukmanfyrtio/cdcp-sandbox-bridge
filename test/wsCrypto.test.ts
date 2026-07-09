import { randomBytes } from "crypto";
import { describe, expect, it } from "vitest";
import { decryptJson, encryptJson, loadOrGenerateKey } from "../src/wsCrypto";

describe("encryptJson / decryptJson", () => {
  const key = randomBytes(32);

  it("round-trips an arbitrary JSON value", () => {
    const value = { pan: "4111111111111111", track2: "4111...D2812...", nested: { a: [1, 2, 3] } };
    const payload = encryptJson(key, value);
    expect(decryptJson(key, payload)).toEqual(value);
  });

  it("produces a different ciphertext each time (random IV), even for the same input", () => {
    const value = { pan: "4111111111111111" };
    const a = encryptJson(key, value);
    const b = encryptJson(key, value);
    expect(a.iv).not.toBe(b.iv);
    expect(a.data).not.toBe(b.data);
  });

  it("throws instead of silently returning garbage when the ciphertext is tampered with", () => {
    const payload = encryptJson(key, { pan: "4111111111111111" });
    const tampered = { iv: payload.iv, data: payload.data.slice(0, -2) + (payload.data.slice(-2) === "00" ? "01" : "00") };
    expect(() => decryptJson(key, tampered)).toThrow();
  });

  it("throws when decrypted with the wrong key", () => {
    const payload = encryptJson(key, { pan: "4111111111111111" });
    expect(() => decryptJson(randomBytes(32), payload)).toThrow();
  });
});

describe("loadOrGenerateKey", () => {
  it("uses the provided hex env value when it's exactly 32 bytes", () => {
    const hex = randomBytes(32).toString("hex");
    const key = loadOrGenerateKey(hex, () => {});
    expect(key.toString("hex")).toBe(hex);
  });

  it("rejects an env value of the wrong length instead of silently truncating/padding", () => {
    expect(() => loadOrGenerateKey(randomBytes(16).toString("hex"), () => {})).toThrow(/32 bytes/);
  });

  it("generates a fresh 32-byte key and logs it when no env value is set", () => {
    const logs: string[] = [];
    const key = loadOrGenerateKey(undefined, (m) => logs.push(m));
    expect(key.length).toBe(32);
    expect(logs.some((l) => l.includes(key.toString("hex")))).toBe(true);
  });
});
