// Terminal Verification Results (tag 95, 5 bytes) / Transaction Status Information (tag 9B, 2
// bytes) — EMV Book 3 Annex C. Built from the actual checks this bridge runs, replacing the old
// hardcoded-zero placeholders.
import { bytesToHex } from "./hex";
import { CvmOutcome } from "./cvm";

const B8 = 0x80, B7 = 0x40, B6 = 0x20, B5 = 0x10, B4 = 0x08, B3 = 0x04;

// TVR byte4 b8 ("transaction exceeds floor limit") — a separate concept from CVM (cvm.ts is now
// entirely card-driven), purely about whether the terminal itself flags this amount as high-risk.
export const TERMINAL_FLOOR_LIMIT_IDR = 1_000_000;

function todayYYMMDD(today: Date): string {
  return `${String(today.getFullYear() % 100).padStart(2, "0")}${String(today.getMonth() + 1).padStart(
    2,
    "0"
  )}${String(today.getDate()).padStart(2, "0")}`;
}

export interface ExpiryCheck {
  expired: boolean;
  notYetEffective: boolean;
}

/** Tags 5F24 (expiration) / 5F25 (effective date), both YYMMDD BCD — absent tag = no adverse finding. */
export function checkExpiry(exp?: Uint8Array, eff?: Uint8Array, today: Date = new Date()): ExpiryCheck {
  const todayStr = todayYYMMDD(today);
  return {
    expired: exp ? bytesToHex(exp).slice(0, 6) < todayStr : false,
    notYetEffective: eff ? bytesToHex(eff).slice(0, 6) > todayStr : false,
  };
}

export interface AucCheck {
  serviceAllowed: boolean;
}

/**
 * Tag 9F07 (Application Usage Control), byte 1: b6 domestic goods, b5 international goods, b1
 * valid at non-ATM terminals. This bridge has no goods-vs-services distinction (always evaluates
 * as goods) — documented simplification, not a spec requirement violation. Tag absent → allowed
 * (EMV default: no AUC present means no restriction).
 */
export function checkAuc(auc: Uint8Array | undefined, domestic: boolean): AucCheck {
  if (!auc || auc.length < 1) return { serviceAllowed: true };
  const byte1 = auc[0];
  const goodsBit = domestic ? 0x20 : 0x10;
  const nonAtmBit = 0x01;
  return { serviceAllowed: (byte1 & goodsBit) !== 0 && (byte1 & nonAtmBit) !== 0 };
}

export interface TerminalRiskManagementResult {
  exceedsFloorLimit: boolean;
  forcedOnline: true;
}

/**
 * "forcedOnline" is unconditionally true — this bridge's whole design is "every sale goes online",
 * so consecutive-offline-limit / random-selection checks (TVR byte4 b7/b6/b5) are structurally
 * inapplicable: they measure velocity on an offline-approval path this terminal never takes. Left
 * at 0 in buildTvr, which is the honest state, not a gap.
 */
export function evaluateTerminalRiskManagement(amountRupiah: number): TerminalRiskManagementResult {
  return { exceedsFloorLimit: amountRupiah > TERMINAL_FLOOR_LIMIT_IDR, forcedOnline: true };
}

export interface TvrInputs {
  odaPerformed: boolean;
  /** True only when SDA ran (odaPerformed) and its signature check came back invalid. */
  sdaFailed: boolean;
  expired: boolean;
  notYetEffective: boolean;
  serviceAllowed: boolean;
  cvmOutcome: CvmOutcome;
  trm: { exceedsFloorLimit: boolean };
}

export function buildTvr(i: TvrInputs): Uint8Array {
  // b8 "ODA not performed" (honest default — no CAPK on file, or card doesn't offer it) / b7 "SDA
  // failed" (oda.ts did run SDA but the signature didn't check out).
  const byte1 = (i.odaPerformed ? 0x00 : B8) | (i.sdaFailed ? B7 : 0);
  const byte2 = (i.expired ? B7 : 0) | (i.notYetEffective ? B6 : 0) | (!i.serviceAllowed ? B5 : 0);
  const byte3 = (i.cvmOutcome.verificationFailed ? B8 : 0) | (i.cvmOutcome.onlinePinRequested ? B3 : 0);
  const byte4 = B4 | (i.trm.exceedsFloorLimit ? B8 : 0); // B4 "merchant forced online" always set
  const byte5 = 0x00; // no TDOL, no issuer script processing, no contactless relay-resistance logic
  return Uint8Array.of(byte1, byte2, byte3, byte4, byte5);
}

export interface TsiInputs {
  cvmVerificationPerformed: boolean;
  cardRiskManagementPerformed: boolean;
}

export function buildTsi(i: TsiInputs): Uint8Array {
  const byte1 = (i.cvmVerificationPerformed ? B7 : 0) | (i.cardRiskManagementPerformed ? B6 : 0) | B4; // B4: terminal risk management always runs
  return Uint8Array.of(byte1, 0x00);
}
