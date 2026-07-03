// Orchestrates the EMV contactless read flow over an abstract transceive function, and extracts
// the cardholder data (PAN, expiry, Track2) needed by the sandbox. Card-scheme quirks (esp. GPO/PDOL)
// may need small tweaks per acquirer — the transceive abstraction keeps this unit-testable.
import { buildGpo, parseAfl, readRecord, selectAid, selectPpse } from "./apdu";
import { bytesToHex } from "./hex";
import { findAllTags, findTag, parseTlv, TlvNode } from "./tlv";

export type Transceive = (capdu: Uint8Array) => Promise<Uint8Array>;

export interface CardData {
  pan: string;
  expiryYYMM: string;
  cardholderName?: string;
  track2?: string;
  scheme?: string;
  aid?: string;
}

function splitSw(rapdu: Uint8Array): { data: Uint8Array; sw: string } {
  if (rapdu.length < 2) return { data: new Uint8Array(0), sw: "0000" };
  return { data: rapdu.slice(0, rapdu.length - 2), sw: bytesToHex(rapdu.slice(rapdu.length - 2)) };
}

function schemeFromAid(aidHex: string): string {
  if (aidHex.startsWith("A000000003")) return "Visa";
  if (aidHex.startsWith("A000000004")) return "Mastercard";
  if (aidHex.startsWith("A000000025")) return "Amex";
  if (aidHex.startsWith("A000000152")) return "Discover";
  if (aidHex.startsWith("A000000065")) return "JCB";
  return "Unknown";
}

/** Parse EMV Track 2 Equivalent Data (tag 57): <PAN> D <YYMM> <service> <discretionary> F-padded. */
export function parseTrack2(track2Hex: string): { pan: string; expiryYYMM: string; track2: string } | null {
  const h = track2Hex.toUpperCase().replace(/F+$/, "");
  const sep = h.indexOf("D");
  if (sep < 0) return null;
  const pan = h.slice(0, sep);
  const rest = h.slice(sep + 1);
  const expiryYYMM = rest.slice(0, 4);
  if (!/^\d+$/.test(pan) || expiryYYMM.length < 4) return null;
  return { pan, expiryYYMM, track2: h };
}

function extractFromRecords(nodes: TlvNode[]): Partial<CardData> {
  const out: Partial<CardData> = {};

  const track2Node = findTag(nodes, "57");
  if (track2Node) {
    const parsed = parseTrack2(bytesToHex(track2Node.value));
    if (parsed) {
      out.pan = parsed.pan;
      out.expiryYYMM = parsed.expiryYYMM;
      out.track2 = parsed.track2;
    }
  }

  if (!out.pan) {
    const panNode = findTag(nodes, "5A");
    if (panNode) out.pan = bytesToHex(panNode.value).replace(/F+$/i, "");
  }
  if (!out.expiryYYMM) {
    const expNode = findTag(nodes, "5F24"); // YYMMDD (BCD)
    if (expNode) out.expiryYYMM = bytesToHex(expNode.value).slice(0, 4);
  }
  const nameNode = findTag(nodes, "5F20");
  if (nameNode) {
    const name = new TextDecoder().decode(nameNode.value).trim();
    if (name) out.cardholderName = name;
  }
  return out;
}

/** Run the full read flow. Throws on a card that never yields a PAN. */
export async function readEmvCard(transceive: Transceive, log: (msg: string) => void = () => {}): Promise<CardData> {
  // 1. SELECT PPSE
  const ppse = splitSw(await transceive(selectPpse()));
  if (ppse.sw !== "9000") throw new Error(`SELECT PPSE failed (SW ${ppse.sw})`);
  const ppseTlv = parseTlv(ppse.data);
  const aidNodes = findAllTags(ppseTlv, "4F");
  if (aidNodes.length === 0) throw new Error("No AID found in PPSE directory");

  let lastError = "";
  for (const aidNode of aidNodes) {
    const aid = aidNode.value;
    const aidHex = bytesToHex(aid);
    log(`SELECT AID ${aidHex}`);

    const sel = splitSw(await transceive(selectAid(aid)));
    if (sel.sw !== "9000") {
      lastError = `SELECT AID ${aidHex} failed (SW ${sel.sw})`;
      continue;
    }
    const fciTlv = parseTlv(sel.data);

    // 2. GET PROCESSING OPTIONS
    const gpo = splitSw(await transceive(buildGpo(fciTlv)));
    if (gpo.sw !== "9000") {
      lastError = `GPO failed for ${aidHex} (SW ${gpo.sw})`;
      continue;
    }

    const collected: TlvNode[] = [];
    let afl: Uint8Array | null = null;

    const gpoTlv = parseTlv(gpo.data);
    const template80 = findTag(gpoTlv, "80"); // Format 1: AIP(2) + AFL(rest)
    if (template80) {
      afl = template80.value.slice(2);
    } else {
      // Format 2 (template 77): may carry AFL (94) and even Track2 (57) directly.
      collected.push(...gpoTlv);
      const aflNode = findTag(gpoTlv, "94");
      if (aflNode) afl = aflNode.value;
    }

    // 3. READ RECORDs per AFL
    if (afl) {
      for (const entry of parseAfl(afl)) {
        for (let rec = entry.firstRecord; rec <= entry.lastRecord; rec++) {
          const rr = splitSw(await transceive(readRecord(rec, entry.sfi)));
          if (rr.sw === "9000" && rr.data.length) collected.push(...parseTlv(rr.data));
        }
      }
    }

    const extracted = extractFromRecords(collected.length ? collected : gpoTlv);
    if (extracted.pan) {
      return {
        pan: extracted.pan,
        expiryYYMM: extracted.expiryYYMM ?? "",
        cardholderName: extracted.cardholderName,
        track2: extracted.track2,
        scheme: schemeFromAid(aidHex),
        aid: aidHex,
      };
    }
    lastError = `No PAN found for AID ${aidHex}`;
  }

  throw new Error(lastError || "Failed to read card");
}
