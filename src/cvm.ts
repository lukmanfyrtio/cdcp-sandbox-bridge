// Cardholder Verification Method processing (EMV Book 3 §10.5 / Annex C5-C6): parses the card's
// CVM List (tag 8E) and walks its rules against what this bridge can actually perform, replacing
// the old amount-only floor-limit heuristic with a real per-card decision.

// The only methods this bridge can actually execute — no offline PIN VERIFY capability (no keypad
// wired to the card side; online PIN entry happens downstream in cdcp-sandbox-web).
export const NO_CVM_REQUIRED = 0x1f;
export const SIGNATURE = 0x1e;
export const ONLINE_PIN = 0x02;
export const SUPPORTED_CVM_METHODS: ReadonlySet<number> = new Set([NO_CVM_REQUIRED, SIGNATURE, ONLINE_PIN]);
const FAIL_CVM_PROCESSING = 0x00;
const NOT_AVAILABLE = 0x3f;

export interface CvmRule {
  continueOnFail: boolean; // CVM Code bit 8: apply succeeding rule if this one is unsuccessful
  method: number; // CVM Code bits 6-1
  condition: number; // CVM Condition Code byte
}

export interface ParsedCvmList {
  amountX: number;
  amountY: number;
  rules: CvmRule[];
}

/** Amount X/Y are 4-byte plain unsigned binary — the one EMV amount field that isn't BCD. */
function readUint32BE(b: Uint8Array, offset: number): number {
  return ((b[offset] * 0x1000000) + (b[offset + 1] << 16) + (b[offset + 2] << 8) + b[offset + 3]) >>> 0;
}

export function parseCvmList(value: Uint8Array): ParsedCvmList | null {
  if (value.length < 8 || (value.length - 8) % 2 !== 0) return null;
  const amountX = readUint32BE(value, 0);
  const amountY = readUint32BE(value, 4);
  const rules: CvmRule[] = [];
  for (let i = 8; i < value.length; i += 2) {
    rules.push({ continueOnFail: (value[i] & 0x80) !== 0, method: value[i] & 0x3f, condition: value[i + 1] });
  }
  return { amountX, amountY, rules };
}

/**
 * Condition 0x03 ("if terminal supports the CVM") is evaluated as always-true here, deferring
 * entirely to the method-support check every rule already gets — that check IS "does the terminal
 * support this CVM", so treating 0x03 as a separate amount-like gate would double up the same test.
 */
function conditionApplies(condition: number, amountRupiah: number, amountX: number): boolean {
  switch (condition) {
    case 0x00: // Always
    case 0x02: // if not unattended cash, not manual cash, no cashback — the normal attended-purchase case
    case 0x03: // if terminal supports the CVM — see doc comment above
      return true;
    case 0x06: // under X
      return amountRupiah < amountX;
    case 0x07: // over X — ">=" so 0x06/0x07 partition the amount space with no gap at the boundary
      return amountRupiah >= amountX;
    case 0x01: // if unattended cash
    case 0x04: // if manual cash
    case 0x05: // if purchase with cashback
    case 0x08: // under Y — Y only has meaning for cashback amounts, never applicable here
    case 0x09: // over Y
      return false;
    default: // RFU / payment-system / issuer-reserved — never invent behavior for undefined codes
      return false;
  }
}

export interface CvmOutcome {
  method: number;
  condition: number;
  result: 0x00 | 0x01 | 0x02; // unknown/not-available · failed · successful
  onlinePinRequested: boolean; // TVR byte3 b3 / CardData.pinRequired
  verificationPerformed: boolean; // TSI byte1 b7
  verificationFailed: boolean; // TVR byte3 b8
}

// `performed` (TSI byte1 b7) tracks whether CVM processing was actually carried out at all — true
// for every case where a real CVM List was walked, even if the outcome was failure. It's only false
// when there was no list to process in the first place. This is distinct from `result`/`verificationFailed`
// (TVR byte3 b8), which tracks whether that processing *succeeded*.
function outcome(method: number, condition: number, result: 0x00 | 0x01 | 0x02, performed: boolean): CvmOutcome {
  return {
    method,
    condition,
    result,
    onlinePinRequested: method === ONLINE_PIN && result !== 0x01,
    verificationPerformed: performed,
    verificationFailed: result === 0x01,
  };
}

export function evaluateCvm(cvmListValue: Uint8Array | null, amountRupiah: number): CvmOutcome {
  if (!cvmListValue) return outcome(NOT_AVAILABLE, 0x00, 0x00, false);
  const parsed = parseCvmList(cvmListValue);
  if (!parsed) return outcome(NOT_AVAILABLE, 0x00, 0x00, false);

  for (const rule of parsed.rules) {
    if (!conditionApplies(rule.condition, amountRupiah, parsed.amountX)) continue;

    if (rule.method === FAIL_CVM_PROCESSING) {
      // A directive, not a capability — "apply next rule" doesn't apply to it.
      return outcome(NOT_AVAILABLE, rule.condition, 0x01, true);
    }
    if (SUPPORTED_CVM_METHODS.has(rule.method)) {
      // Online PIN and Signature both report "unknown" (0x00), not "successful" (0x02): neither
      // is actually confirmed yet at this point — online PIN's result comes back from the issuer
      // later, and signature is checked by the cashier by eye after the receipt prints. Matches the
      // real production app's convention (EmvViewModel.kt), which never claims success this early.
      const result = rule.method === NO_CVM_REQUIRED ? 0x02 : 0x00;
      return outcome(rule.method, rule.condition, result, true);
    }
    if (rule.continueOnFail) continue;
    // Condition matched a real rule we just can't execute — report what was attempted, not 0x3F.
    return outcome(rule.method, rule.condition, 0x01, true);
  }
  return outcome(NOT_AVAILABLE, 0x00, 0x01, true);
}

export function encodeCvmResults(o: CvmOutcome): Uint8Array {
  return Uint8Array.of(o.method & 0x3f, o.condition, o.result);
}
