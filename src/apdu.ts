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

/** Default terminal values for PDOL tags, keyed by uppercase hex tag. Tunable per acquirer/scheme. */
function defaultPdolValue(tag: string, length: number): Uint8Array {
  const out = new Uint8Array(length);
  const set = (hex: string) => {
    const b = hexToBytes(hex);
    out.set(b.slice(0, length), Math.max(0, length - b.length));
  };
  switch (tag) {
    case "9F66": // TTQ (Terminal Transaction Qualifiers) — Visa qVSDC + contactless read
      set("36000000");
      break;
    case "9F02": // Amount, Authorised (BCD)
      set("000000000100");
      break;
    case "9F03": // Amount, Other
      set("000000000000");
      break;
    case "9F1A": // Terminal Country Code (ID = 0360)
      set("0360");
      break;
    case "5F2A": // Transaction Currency Code (IDR = 0360)
      set("0360");
      break;
    case "95": // Terminal Verification Results
      set("0000000000");
      break;
    case "9A": {
      // Transaction Date YYMMDD
      const d = new Date();
      set(
        `${String(d.getFullYear() % 100).padStart(2, "0")}${String(d.getMonth() + 1).padStart(2, "0")}${String(
          d.getDate()
        ).padStart(2, "0")}`
      );
      break;
    }
    case "9C": // Transaction Type
      set("00");
      break;
    case "9F37": {
      // Unpredictable Number (random)
      for (let i = 0; i < length; i++) out[i] = Math.floor(Math.random() * 256);
      break;
    }
    case "9F35": // Terminal Type
      set("22");
      break;
    case "9F40": // Additional Terminal Capabilities
      set("6000000000");
      break;
    case "9F4E": // Merchant Name and Location
      break; // zeros
    default:
      break; // zeros of requested length
  }
  return out;
}

/** Parse a PDOL (Tag-Length list) and produce the concatenated data object list values. */
export function buildPdolData(pdol: Uint8Array): Uint8Array {
  const parts: Uint8Array[] = [];
  let i = 0;
  while (i < pdol.length) {
    // tag
    const tagStart = i;
    let tagByte = pdol[i++];
    if ((tagByte & 0x1f) === 0x1f) {
      while (i < pdol.length && (pdol[i] & 0x80) !== 0) i++;
      i++;
    }
    const tag = bytesToHex(pdol.slice(tagStart, i));
    // length
    let length = pdol[i++];
    if (length & 0x80) {
      const n = length & 0x7f;
      length = 0;
      for (let k = 0; k < n; k++) length = (length << 8) | pdol[i++];
    }
    parts.push(defaultPdolValue(tag, length));
  }
  return concat(...parts);
}

/** Build a GET PROCESSING OPTIONS APDU. If the AID's FCI carries a PDOL, fill it; else send empty 83 00. */
export function buildGpo(selectAidResponseTlv: TlvNode[]): Uint8Array {
  const pdolNode = findFirst(selectAidResponseTlv, "9F38");
  let commandData: Uint8Array;
  if (pdolNode && pdolNode.value.length > 0) {
    const pdolValues = buildPdolData(pdolNode.value);
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
