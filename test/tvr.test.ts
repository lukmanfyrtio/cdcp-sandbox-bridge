import { describe, expect, it } from "vitest";
import { evaluateCvm } from "../src/cvm";
import { bytesToHex, hexToBytes } from "../src/hex";
import { buildTsi, buildTvr, checkAuc, checkExpiry, evaluateTerminalRiskManagement, TERMINAL_FLOOR_LIMIT_IDR } from "../src/tvr";

const TODAY = new Date(2026, 6, 8); // 2026-07-08, month is 0-indexed

describe("checkExpiry", () => {
  it("finds nothing adverse when both tags are absent", () => {
    expect(checkExpiry(undefined, undefined, TODAY)).toEqual({ expired: false, notYetEffective: false });
  });

  it("flags an expiration date before today", () => {
    expect(checkExpiry(hexToBytes("251231"), undefined, TODAY).expired).toBe(true);
    expect(checkExpiry(hexToBytes("270101"), undefined, TODAY).expired).toBe(false);
  });

  it("flags an effective date after today", () => {
    expect(checkExpiry(undefined, hexToBytes("270101"), TODAY).notYetEffective).toBe(true);
    expect(checkExpiry(undefined, hexToBytes("250101"), TODAY).notYetEffective).toBe(false);
  });
});

describe("checkAuc", () => {
  it("allows the service when the tag is absent (EMV default: no AUC = no restriction)", () => {
    expect(checkAuc(undefined, true).serviceAllowed).toBe(true);
  });

  it("checks the domestic/international goods bit plus the non-ATM bit", () => {
    expect(checkAuc(hexToBytes("2100"), true).serviceAllowed).toBe(true); // domestic goods + non-ATM
    expect(checkAuc(hexToBytes("1100"), true).serviceAllowed).toBe(false); // international goods only, checked as domestic
    expect(checkAuc(hexToBytes("1100"), false).serviceAllowed).toBe(true); // international goods + non-ATM, checked as international
    expect(checkAuc(hexToBytes("2000"), true).serviceAllowed).toBe(false); // domestic goods set, but non-ATM bit missing
  });
});

describe("evaluateTerminalRiskManagement", () => {
  it("flags amounts over the floor limit, always forces online", () => {
    expect(evaluateTerminalRiskManagement(TERMINAL_FLOOR_LIMIT_IDR)).toEqual({ exceedsFloorLimit: false, forcedOnline: true });
    expect(evaluateTerminalRiskManagement(TERMINAL_FLOOR_LIMIT_IDR + 1)).toEqual({ exceedsFloorLimit: true, forcedOnline: true });
  });
});

describe("buildTvr / buildTsi", () => {
  const noCvmOutcome = evaluateCvm(hexToBytes("00000000" + "00000000" + "1F00"), 0); // No CVM Required
  const onlinePinOutcome = evaluateCvm(hexToBytes("00000000" + "00000000" + "0200"), 0); // Online PIN
  const failedOutcome = evaluateCvm(hexToBytes("00000000" + "00000000" + "0100"), 0); // unsupported, no continue → fails

  it("sets only the always-on bits when nothing else applies", () => {
    const tvr = buildTvr({
      odaPerformed: false,
      sdaFailed: false,
      expired: false,
      notYetEffective: false,
      serviceAllowed: true,
      cvmOutcome: noCvmOutcome,
      trm: { exceedsFloorLimit: false },
    });
    // byte1 b8 (ODA not performed) + byte4 b4 (merchant forced online) — everything else honestly 0.
    expect(bytesToHex(tvr)).toBe("8000000800");
  });

  it("sets the floor-limit bit and the online-PIN-requested bit", () => {
    const tvr = buildTvr({
      odaPerformed: false,
      sdaFailed: false,
      expired: false,
      notYetEffective: false,
      serviceAllowed: true,
      cvmOutcome: onlinePinOutcome,
      trm: { exceedsFloorLimit: true },
    });
    expect(bytesToHex(tvr)).toBe("8000048800" /* byte3 b3=04 online PIN, byte4 b8|b4=88 */);
  });

  it("sets expiry, usage-control, and CVM-failed bits", () => {
    const tvr = buildTvr({
      odaPerformed: false,
      sdaFailed: false,
      expired: true,
      notYetEffective: false,
      serviceAllowed: false,
      cvmOutcome: failedOutcome,
      trm: { exceedsFloorLimit: false },
    });
    expect(bytesToHex(tvr)).toBe("8050800800" /* byte2 b7|b5=50 (expired + service not allowed), byte3 b8=80 (cvm failed) */);
  });

  it("sets the SDA-failed bit only when ODA was performed and came back invalid", () => {
    const tvr = buildTvr({
      odaPerformed: true,
      sdaFailed: true,
      expired: false,
      notYetEffective: false,
      serviceAllowed: true,
      cvmOutcome: noCvmOutcome,
      trm: { exceedsFloorLimit: false },
    });
    // byte1: b8 stays 0 (ODA WAS performed) but b7=40 (SDA failed) — 40, not 80|40.
    expect(bytesToHex(tvr)).toBe("4000000800");
  });

  it("TSI reflects performed steps — terminal risk management always, CVM/card risk management/ODA only when actually run", () => {
    expect(bytesToHex(buildTsi({ odaPerformed: false, cvmVerificationPerformed: false, cardRiskManagementPerformed: false }))).toBe(
      "0800"
    );
    expect(bytesToHex(buildTsi({ odaPerformed: false, cvmVerificationPerformed: true, cardRiskManagementPerformed: true }))).toBe(
      "6800"
    );
    expect(bytesToHex(buildTsi({ odaPerformed: true, cvmVerificationPerformed: true, cardRiskManagementPerformed: true }))).toBe(
      "E800"
    );
  });
});
