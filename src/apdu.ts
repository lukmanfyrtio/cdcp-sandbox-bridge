// APDU builders for the EMV contactless read flow, plus a PDOL value builder.
import { bytesToHex, concat, hexToBytes } from "./hex";
import { parseTlv, TlvNode } from "./tlv";

const PPSE_NAME = hexToBytes("325041592E5359532E4444463031"); // "2PAY.SYS.DDF01"

export function selectPpse(): Uint8Array {
  return concat(hexToBytes("00A40400"), Uint8Array.of(PPSE_NAME.length), PPSE_NAME, Uint8Array.of(0x00));
}

export function selectAid(aid: Uint8Array): Uint8Array {
  return concat(hexToBytes("00A40400"), Uint8Array.of(aid.length), aid, Uint8Array.of(0x00));
}

export function readRecord(record: number, sfi: number): Uint8Array {
  const p2 = ((sfi << 3) | 0x04) & 0xff;
  return Uint8Array.of(0x00, 0xb2, record, p2, 0x00);
}

// EMV requires a per-transaction counter (9F41) that increments across the terminal's lifetime,
// not per card. In-memory only — resets on bridge restart, which is fine for a sandbox but would
// need real persistence on an actual terminal.
let transactionSequenceCounter = 0;

/**
 * Terminal-generated values for a real transaction — amount comes from the user's actual input
 * (must be known before GENERATE AC, since the cryptogram is computed over it), the rest are
 * either fixed sandbox terminal config or generated fresh per transaction (date, unpredictable
 * number, sequence counter). Reused for BOTH the CDOL1 fill (sent to the card) and the field 55
 * tag collection (sent to the host) so the two always agree on what was actually used.
 *
 * Tag set mirrors the real EDC SDK's rfTags.json config (verified against edc-sdk/pax's
 * EmvTransaction.kt). Notably absent: 95 (TVR), 9B (TSI), 9F34 (CVM Results) — those depend on the
 * card's own data (CVM List, expiry, usage control) which isn't known until after READ RECORD, so
 * they're computed in emv.ts (via cvm.ts/tvr.ts) once records are in hand, not generated here.
 */
export function generateTerminalTags(amountRupiah: number): Record<string, Uint8Array> {
  const amountCents = Math.max(0, Math.round(amountRupiah));
  const un = new Uint8Array(4);
  for (let i = 0; i < 4; i++) un[i] = Math.floor(Math.random() * 256);
  const d = new Date();
  const dateHex = `${String(d.getFullYear() % 100).padStart(2, "0")}${String(d.getMonth() + 1).padStart(
    2,
    "0"
  )}${String(d.getDate()).padStart(2, "0")}`;
  transactionSequenceCounter = (transactionSequenceCounter + 1) % 100000000;

  return {
    "9F02": hexToBytes(amountCents.toString().padStart(12, "0")), // Amount, Authorised (BCD)
    "9F03": hexToBytes("000000000000"), // Amount, Other
    "9F1A": hexToBytes("0360"), // Terminal Country Code (ID)
    "5F2A": hexToBytes("0360"), // Transaction Currency Code (IDR)
    "9A": hexToBytes(dateHex), // Transaction Date YYMMDD
    "9C": hexToBytes("00"), // Transaction Type — 00 = purchase
    "9F37": un, // Unpredictable Number
    "9F66": hexToBytes("36000000"), // TTQ (Visa qVSDC + contactless read)
    "9F35": hexToBytes("22"), // Terminal Type — attended, online-capable
    "9F40": hexToBytes("6000000000"), // Additional Terminal Capabilities
    // Terminal Capabilities — only claims what this bridge can actually execute: signature +
    // online PIN + no-CVM-required (no offline PIN VERIFY support), no SDA/DDA/CDA (oda.ts never
    // runs real verification). Was E0F8C8, which over-claimed both.
    "9F33": hexToBytes("E01800"),
    "9F15": hexToBytes("5999"), // Merchant Category Code — sandbox default (misc. retail)
    "9F41": hexToBytes(transactionSequenceCounter.toString().padStart(8, "0")), // Transaction Sequence Counter
  };
}

function fitLength(value: Uint8Array, length: number): Uint8Array {
  if (value.length === length) return value;
  const out = new Uint8Array(length);
  out.set(value.slice(0, length), Math.max(0, length - value.length));
  return out;
}

/**
 * Parse a DOL (PDOL or CDOL1/2 — same Tag-Length-list format) and produce the concatenated data
 * object list values, using `terminalTags` where available and zeros for anything unrecognized.
 */
export function buildPdolData(dol: Uint8Array, terminalTags: Record<string, Uint8Array> = generateTerminalTags(0)): Uint8Array {
  const parts: Uint8Array[] = [];
  let i = 0;
  while (i < dol.length) {
    // tag
    const tagStart = i;
    let tagByte = dol[i++];
    if ((tagByte & 0x1f) === 0x1f) {
      while (i < dol.length && (dol[i] & 0x80) !== 0) i++;
      i++;
    }
    const tag = bytesToHex(dol.slice(tagStart, i));
    // length
    let length = dol[i++];
    if (length & 0x80) {
      const n = length & 0x7f;
      length = 0;
      for (let k = 0; k < n; k++) length = (length << 8) | dol[i++];
    }
    parts.push(terminalTags[tag] ? fitLength(terminalTags[tag], length) : new Uint8Array(length));
  }
  return concat(...parts);
}

/**
 * GENERATE AC — the step our old flow skipped entirely. This is what makes the real chip produce
 * the Application Cryptogram (9F26): the terminal fills the card's own CDOL1 with real transaction
 * data (amount, date, unpredictable number, ...) and the card computes a cryptogram over it using
 * keys that never leave the chip. P1=0x80 requests ARQC (online authorization) — the only mode this
 * sandbox uses, since every sale goes through sale_trx online regardless.
 */
export function buildGenerateAc(cdol1Data: Uint8Array): Uint8Array {
  return concat(hexToBytes("80AE8000"), Uint8Array.of(cdol1Data.length), cdol1Data, Uint8Array.of(0x00));
}

/**
 * Build a GET PROCESSING OPTIONS APDU. If the AID's FCI carries a PDOL, fill it with the real
 * terminalTags for this transaction; else send empty 83 00.
 *
 * `terminalTags` MUST reflect the real amount (not the generateTerminalTags(0) default) — some
 * contactless cards pick a limited/no-CDOL "fast path" when PDOL amount is zero, since that reads
 * as a non-financial/zero-value tap, which silently skips GENERATE AC for a real transaction.
 */
export function buildGpo(selectAidResponseTlv: TlvNode[], terminalTags: Record<string, Uint8Array> = generateTerminalTags(0)): Uint8Array {
  const pdolNode = findFirst(selectAidResponseTlv, "9F38");
  let commandData: Uint8Array;
  if (pdolNode && pdolNode.value.length > 0) {
    const pdolValues = buildPdolData(pdolNode.value, terminalTags);
    commandData = concat(Uint8Array.of(0x83, pdolValues.length), pdolValues);
  } else {
    commandData = hexToBytes("8300");
  }
  return concat(hexToBytes("80A80000"), Uint8Array.of(commandData.length), commandData, Uint8Array.of(0x00));
}

function findFirst(nodes: TlvNode[], tag: string): TlvNode | null {
  const target = tag.toUpperCase();
  for (const n of nodes) {
    if (n.tag === target) return n;
    if (n.children.length) {
      const hit = findFirst(n.children, target);
      if (hit) return hit;
    }
  }
  return null;
}

/** AFL is groups of 4 bytes: [SFI<<3 | ..][firstRec][lastRec][#recs for offline auth]. */
export interface AflEntry {
  sfi: number;
  firstRecord: number;
  lastRecord: number;
}

export function parseAfl(afl: Uint8Array): AflEntry[] {
  const entries: AflEntry[] = [];
  for (let i = 0; i + 3 < afl.length; i += 4) {
    entries.push({ sfi: afl[i] >> 3, firstRecord: afl[i + 1], lastRecord: afl[i + 2] });
  }
  return entries;
}

export { parseTlv };
