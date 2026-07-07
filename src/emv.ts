// Orchestrates the EMV contactless read flow over an abstract transceive function, and extracts
// the cardholder data (PAN, expiry, Track2) needed by the sandbox. Card-scheme quirks (esp. GPO/PDOL)
// may need small tweaks per acquirer — the transceive abstraction keeps this unit-testable.
import { buildGenerateAc, buildGpo, buildPdolData, generateTerminalTags, parseAfl, readRecord, selectAid, selectPpse } from "./apdu";
import { bytesToHex, concat, hexToBytes } from "./hex";
import { findAllTags, findTag, parseTlv, TlvNode } from "./tlv";

export type Transceive = (capdu: Uint8Array) => Promise<Uint8Array>;

export interface CardData {
  pan: string;
  expiryYYMM: string;
  cardholderName?: string;
  track2?: string;
  scheme?: string;
  aid?: string;
  /**
   * Hex TLV blob — the sandbox's equivalent of ISO 8583 field 55 (ICC System Related Data), built
   * from a real GENERATE AC exchange with the tapped card when its records carry a CDOL1 (tag 8C).
   * Undefined if the card had no CDOL1 (GAC skipped) — see readEmvCard for why.
   */
  emvData?: string;
  /**
   * Every tag/value pair actually present in the card's GPO response + records (and, if it ran,
   * the GENERATE AC response) — a raw dump for exploring what a real card carries, beyond just the
   * curated fields above. Tag order is depth-first / read order, duplicates possible across records.
   */
  allTags?: { tag: string; value: string }[];
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

/** BER-TLV encode a single tag/value pair (short or long-form length as needed). */
function encodeTlv(tagHex: string, value: Uint8Array): Uint8Array {
  const tagBytes = hexToBytes(tagHex);
  let lengthBytes: Uint8Array;
  if (value.length < 0x80) {
    lengthBytes = Uint8Array.of(value.length);
  } else {
    const lenBytes: number[] = [];
    let n = value.length;
    while (n > 0) {
      lenBytes.unshift(n & 0xff);
      n >>= 8;
    }
    lengthBytes = concat(Uint8Array.of(0x80 | lenBytes.length), Uint8Array.from(lenBytes));
  }
  return concat(tagBytes, lengthBytes, value);
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

/** Flat tag/value dump of a TLV tree, depth-first, for diagnostic logging and exploration. */
function flattenTlv(nodes: TlvNode[]): { tag: string; value: string }[] {
  const out: { tag: string; value: string }[] = [];
  for (const n of nodes) {
    out.push({ tag: n.tag, value: bytesToHex(n.value) });
    if (n.children.length) out.push(...flattenTlv(n.children));
  }
  return out;
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
  // 5F20 (Cardholder Name) is the normal tag; 9F0B (Cardholder Name Extended) only appears when the
  // name is too long for 5F20 (>26 chars) and should be preferred over it when both are present.
  const nameNode = findTag(nodes, "9F0B") ?? findTag(nodes, "5F20");
  if (nameNode) {
    const name = new TextDecoder().decode(nameNode.value).trim();
    if (name) out.cardholderName = name;
  }
  return out;
}

/**
 * GENERATE AC response comes back in one of two formats (card's choice, not ours):
 *  - Format 1 (primitive tag 80): CID(1) + ATC(2) + AC(8) + [IAD(rest)] concatenated raw.
 *  - Format 2 (constructed tag 77): individual 9F27/9F36/9F26/9F10 sub-TLVs.
 * Mirrors the same dual-format handling GPO already needs (template 80 vs 77).
 */
function parseGenerateAcResponse(data: Uint8Array): { cid?: Uint8Array; atc?: Uint8Array; ac?: Uint8Array; iad?: Uint8Array } {
  const nodes = parseTlv(data);
  const template80 = findTag(nodes, "80");
  if (template80 && template80.value.length >= 11) {
    const v = template80.value;
    return { cid: v.slice(0, 1), atc: v.slice(1, 3), ac: v.slice(3, 11), iad: v.length > 11 ? v.slice(11) : undefined };
  }
  return {
    cid: findTag(nodes, "9F27")?.value,
    atc: findTag(nodes, "9F36")?.value,
    ac: findTag(nodes, "9F26")?.value,
    iad: findTag(nodes, "9F10")?.value,
  };
}

/**
 * Run the full read flow, including GENERATE AC when the card's records carry a CDOL1 — this is
 * what actually produces field 55 (ICC data) for the host, not just the PAN/Track2 a plain
 * READ RECORD gives you. `amountRupiah` must be the real transaction amount: the cryptogram is
 * computed over it, so it has to be known before the tap, not filled in afterward.
 */
export async function readEmvCard(
  transceive: Transceive,
  amountRupiah = 0,
  log: (msg: string) => void = () => {}
): Promise<CardData> {
  let emvData: string | undefined;

  // 1. SELECT PPSE
  const ppse = splitSw(await transceive(selectPpse()));
  if (ppse.sw !== "9000") throw new Error(`SELECT PPSE failed (SW ${ppse.sw})`);
  const ppseTlv = parseTlv(ppse.data);
  const aidNodes = findAllTags(ppseTlv, "4F");
  if (aidNodes.length === 0) throw new Error("No AID found in PPSE directory");
  log(`PPSE OK — ${aidNodes.length} AID(s) offered`);

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

    // Generate once, up front, so the PDOL fill (GPO) and CDOL1 fill (GENERATE AC) agree on the
    // real amount — a zero/placeholder PDOL amount makes some cards pick a limited "fast path"
    // read with no CDOL1 at all, silently skipping GENERATE AC for what is actually a real sale.
    const terminalTags = generateTerminalTags(amountRupiah);

    // 2. GET PROCESSING OPTIONS
    const gpo = splitSw(await transceive(buildGpo(fciTlv, terminalTags)));
    if (gpo.sw !== "9000") {
      lastError = `GPO failed for ${aidHex} (SW ${gpo.sw})`;
      continue;
    }

    const collected: TlvNode[] = [];
    let afl: Uint8Array | null = null;
    let aip: Uint8Array | null = null;

    const gpoTlv = parseTlv(gpo.data);
    const template80 = findTag(gpoTlv, "80"); // Format 1: AIP(2) + AFL(rest)
    if (template80) {
      aip = template80.value.slice(0, 2);
      afl = template80.value.slice(2);
    } else {
      // Format 2 (template 77): may carry AFL (94) and even Track2 (57) directly.
      collected.push(...gpoTlv);
      const aflNode = findTag(gpoTlv, "94");
      if (aflNode) afl = aflNode.value;
      const aipNode = findTag(gpoTlv, "82");
      if (aipNode) aip = aipNode.value;
    }
    log(`GPO OK — AIP=${aip ? bytesToHex(aip) : "?"}`);

    // 3. READ RECORDs per AFL
    if (afl) {
      for (const entry of parseAfl(afl)) {
        for (let rec = entry.firstRecord; rec <= entry.lastRecord; rec++) {
          const rr = splitSw(await transceive(readRecord(rec, entry.sfi)));
          if (rr.sw === "9000" && rr.data.length) {
            const recordNodes = parseTlv(rr.data);
            collected.push(...recordNodes);
            log(`READ RECORD sfi=${entry.sfi} rec=${rec} OK — tags: ${recordNodes.map((n) => n.tag).join(",") || "(none)"}`);
          } else {
            log(`READ RECORD sfi=${entry.sfi} rec=${rec} FAILED (SW ${rr.sw})`);
          }
        }
      }
    }

    const extracted = extractFromRecords(collected.length ? collected : gpoTlv);
    if (!extracted.pan) {
      lastError = `No PAN found for AID ${aidHex}`;
      continue;
    }
    log(`PAN ${extracted.pan.slice(0, 6)}******${extracted.pan.slice(-4)}, exp ${extracted.expiryYYMM}, scheme ${schemeFromAid(aidHex)}`);
    if (extracted.cardholderName) log(`Cardholder name: ${extracted.cardholderName}`);

    const recordsTlv = collected.length ? collected : gpoTlv;
    const allTags = flattenTlv(recordsTlv);
    log(`All tags read from card (${allTags.length}): ${allTags.map((t) => `${t.tag}=${t.value}`).join(" ")}`);

    const cardTag = (tag: string) => {
      const node = findTag(recordsTlv, tag);
      return node ? encodeTlv(tag, node.value) : null;
    };
    const buildField55 = (gac?: { cid?: Uint8Array; atc?: Uint8Array; ac?: Uint8Array; iad?: Uint8Array }) => {
      const parts = [
        aip ? encodeTlv("82", aip) : null,
        encodeTlv("84", aid),
        encodeTlv("95", terminalTags["95"]),
        encodeTlv("9A", terminalTags["9A"]),
        encodeTlv("9C", terminalTags["9C"]),
        encodeTlv("5F2A", terminalTags["5F2A"]),
        cardTag("5F34"), // PAN Sequence Number
        encodeTlv("9F02", terminalTags["9F02"]),
        encodeTlv("9F03", terminalTags["9F03"]),
        gac?.iad ? encodeTlv("9F10", gac.iad) : cardTag("9F10"),
        encodeTlv("9F1A", terminalTags["9F1A"]),
        gac?.ac ? encodeTlv("9F26", gac.ac) : cardTag("9F26"),
        gac?.cid ? encodeTlv("9F27", gac.cid) : cardTag("9F27"),
        encodeTlv("9F33", terminalTags["9F33"]),
        encodeTlv("9F34", terminalTags["9F34"]),
        encodeTlv("9F35", terminalTags["9F35"]),
        gac?.atc ? encodeTlv("9F36", gac.atc) : cardTag("9F36"),
        encodeTlv("9F37", terminalTags["9F37"]),
        encodeTlv("9F06", aid), // AID known to the terminal — same value as 84 here
        cardTag("50"), // Application Label
        cardTag("9F12"), // Application Preferred Name
        encodeTlv("9B", terminalTags["9B"]),
        cardTag("5F28"), // Issuer Country Code
        encodeTlv("4F", aid), // AID from the card's DF Name — same value as 84/9F06 here
        encodeTlv("9F41", terminalTags["9F41"]),
        cardTag("9F6E"), // Form Factor Indicator — rarely present on physical cards
        encodeTlv("9F15", terminalTags["9F15"]),
      ].filter((p): p is Uint8Array => p !== null);

      return bytesToHex(concat(...parts));
    };

    emvData = buildField55();

    // 4. GENERATE AC — only possible if the card's records carry a CDOL1 (tag 8C). Some synthetic/
    // test fixtures won't have one; real cards always do, UNLESS the GPO's PDOL was filled with a
    // zero/placeholder amount and the card chose a limited "fast path" read as a result.
    const cdol1Node = findTag(collected.length ? collected : gpoTlv, "8C");
    if (cdol1Node) {
      const cdol1Data = buildPdolData(cdol1Node.value, terminalTags);
      log(`CDOL1 found (${cdol1Node.value.length} byte) — sending GENERATE AC (ARQC) for amount ${amountRupiah}`);

      const gac = splitSw(await transceive(buildGenerateAc(cdol1Data)));
      if (gac.sw === "9000") {
        const { cid, atc, ac, iad } = parseGenerateAcResponse(gac.data);
        if (ac) {
          // Decoded, not raw — the response's own TLV shape (Format 1 vs 2) differs per card, but
          // these are always the same 4 logical fields regardless, so the dump is consistent.
          allTags.push({ tag: "9F26", value: bytesToHex(ac) });
          if (cid) allTags.push({ tag: "9F27", value: bytesToHex(cid) });
          if (atc) allTags.push({ tag: "9F36", value: bytesToHex(atc) });
          if (iad) allTags.push({ tag: "9F10", value: bytesToHex(iad) });
          log(`GENERATE AC OK — cryptogram ${bytesToHex(ac)}, CID=${cid ? bytesToHex(cid) : "?"}, ATC=${atc ? bytesToHex(atc) : "?"}`);

          // Tag set + order verified against the real EDC SDK's rfTags.json config
          // (edc-sdk/pax's EmvTransaction.kt:getTagList) — not our own invention. A few tags that
          // config includes are skipped: 9F7C (Merchant Custom Data) has no defined use case here.
          emvData = buildField55({ cid, atc, ac, iad });
          log(`Field 55 assembled (${emvData.length / 2} byte): ${emvData}`);
        } else {
          log(`GENERATE AC returned 9000 but no cryptogram in response — emvData left empty`);
        }
      } else {
        log(`GENERATE AC failed (SW ${gac.sw}) — emvData left empty`);
      }
    } else {
      log(`No CDOL1 (8C) in card records — skipping GENERATE AC, using read tags for emvData.`);
    }

    return {
      pan: extracted.pan,
      expiryYYMM: extracted.expiryYYMM ?? "",
      cardholderName: extracted.cardholderName,
      track2: extracted.track2,
      scheme: schemeFromAid(aidHex),
      allTags,
      aid: aidHex,
      emvData,
    };
  }

  throw new Error(lastError || "Failed to read card");
}
