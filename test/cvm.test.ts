import { describe, expect, it } from "vitest";
import { encodeCvmResults, evaluateCvm, parseCvmList } from "../src/cvm";
import { bytesToHex, hexToBytes } from "../src/hex";

function cvmList(amountXHex: string, amountYHex: string, rulesHex: string): Uint8Array {
  return hexToBytes(amountXHex + amountYHex + rulesHex);
}

describe("parseCvmList", () => {
  it("parses amount X/Y as big-endian binary (not BCD) and the rule list", () => {
    const parsed = parseCvmList(cvmList("000F4240", "00000000", "8207" + "1F00"));
    expect(parsed).not.toBeNull();
    expect(parsed!.amountX).toBe(1_000_000);
    expect(parsed!.amountY).toBe(0);
    expect(parsed!.rules).toEqual([
      { continueOnFail: true, method: 0x02, condition: 0x07 },
      { continueOnFail: false, method: 0x1f, condition: 0x00 },
    ]);
  });

  it("returns null for a malformed (too short / odd-remainder) list", () => {
    expect(parseCvmList(hexToBytes("0000"))).toBeNull();
    expect(parseCvmList(hexToBytes("000000000000000000"))).toBeNull(); // 9 bytes: odd remainder after the 8-byte header
  });
});

describe("evaluateCvm", () => {
  it("reports not-available/unknown when there is no CVM List at all", () => {
    const o = evaluateCvm(null, 150000);
    expect(o.method).toBe(0x3f);
    expect(o.result).toBe(0x00);
    expect(o.onlinePinRequested).toBe(false);
    expect(o.verificationPerformed).toBe(false);
    expect(o.verificationFailed).toBe(false);
  });

  it("picks the first rule whose condition is Always and method is supported", () => {
    const o = evaluateCvm(cvmList("00000000", "00000000", "1F00"), 150000);
    expect(o.method).toBe(0x1f);
    expect(o.result).toBe(0x02);
    expect(o.verificationPerformed).toBe(true);
    expect(o.verificationFailed).toBe(false);
  });

  it("marks Online PIN's result as unknown (0x00), never successful, at selection time", () => {
    const o = evaluateCvm(cvmList("00000000", "00000000", "0200"), 150000); // method 0x02, condition Always
    expect(o.method).toBe(0x02);
    expect(o.result).toBe(0x00);
    expect(o.onlinePinRequested).toBe(true);
  });

  it("marks Signature's result as unknown (0x00) too — the cashier checks it by eye after the fact", () => {
    // Matches the real production app's convention (never claims signature success at GAC time).
    const o = evaluateCvm(cvmList("00000000", "00000000", "1E00"), 0); // method 0x1E, condition Always
    expect(o.method).toBe(0x1e);
    expect(o.result).toBe(0x00);
    expect(o.onlinePinRequested).toBe(false);
  });

  it("evaluates under-X / over-X conditions against amount X", () => {
    const underRule = cvmList("000F4240", "00000000", "0206" + "1F00"); // method 0x02 if under X, else No CVM
    expect(evaluateCvm(underRule, 500_000).method).toBe(0x02); // under 1,000,000
    expect(evaluateCvm(underRule, 1_000_000).method).toBe(0x1f); // at/over X: falls through
  });

  it("treats condition 0x03 (terminal supports the CVM) as always-applicable, deferring to the method-support check", () => {
    const o = evaluateCvm(cvmList("00000000", "00000000", "1F03"), 0); // No CVM Required, condition 0x03
    expect(o.method).toBe(0x1f);
    expect(o.result).toBe(0x02);
  });

  it("skips an unsupported method to the next rule when continue-on-fail is set", () => {
    // Rule 1: continue-on-fail + offline plaintext PIN (0x01, unsupported), Always. Rule 2: No CVM Required, Always.
    const o = evaluateCvm(cvmList("00000000", "00000000", "8100" + "1F00"), 0);
    expect(o.method).toBe(0x1f);
    expect(o.result).toBe(0x02);
  });

  it("fails CVM processing on an unsupported method without continue-on-fail, reporting the attempted rule", () => {
    const o = evaluateCvm(cvmList("00000000", "00000000", "0100"), 0); // offline plaintext PIN, no continue bit
    expect(o.method).toBe(0x01);
    expect(o.condition).toBe(0x00);
    expect(o.result).toBe(0x01);
    expect(o.verificationFailed).toBe(true);
  });

  it("fails immediately on the 'fail CVM processing' directive (0x00), ignoring any continue bit", () => {
    const o = evaluateCvm(cvmList("00000000", "00000000", "8000"), 0); // continue bit set, but method is the fail directive
    expect(o.method).toBe(0x3f);
    expect(o.result).toBe(0x01);
  });

  it("fails when the list is exhausted with no applicable rule", () => {
    const o = evaluateCvm(cvmList("00000000", "00000000", "1F01"), 0); // method No CVM, condition "if unattended cash" — never applies here
    expect(o.method).toBe(0x3f);
    expect(o.condition).toBe(0x00);
    expect(o.result).toBe(0x01);
  });
});

describe("encodeCvmResults", () => {
  it("encodes method/condition/result as 3 bytes", () => {
    const o = evaluateCvm(cvmList("00000000", "00000000", "1F00"), 0);
    expect(bytesToHex(encodeCvmResults(o))).toBe("1F0002");
  });
});
