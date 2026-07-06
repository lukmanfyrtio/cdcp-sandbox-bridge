import { describe, expect, it } from "vitest";
import { readEmvCard, parseTrack2, Transceive } from "../src/emv";
import { bytesToHex, concat, hexToBytes } from "../src/hex";
import { findTag, parseTlv } from "../src/tlv";

// Tiny TLV builder for fixtures (assumes value length < 128).
function tlv(tagHex: string, value: Uint8Array): Uint8Array {
  return concat(hexToBytes(tagHex), Uint8Array.of(value.length), value);
}
function withSw(data: Uint8Array, sw = "9000"): Uint8Array {
  return concat(data, hexToBytes(sw));
}
function startsWith(a: Uint8Array, hexPrefix: string): boolean {
  const p = hexToBytes(hexPrefix);
  if (a.length < p.length) return false;
  for (let i = 0; i < p.length; i++) if (a[i] !== p[i]) return false;
  return true;
}

const VISA_AID = hexToBytes("A0000000031010");
const TRACK2_HEX = "4111111111111111D28121010000000000FF"; // PAN 4111.., exp 2812

// PPSE directory pointing at the Visa AID.
const ppseResponse = tlv(
  "6F",
  concat(
    tlv("84", hexToBytes("325041592E5359532E4444463031")),
    tlv("A5", tlv("BF0C", tlv("61", concat(tlv("4F", VISA_AID), tlv("87", hexToBytes("01"))))))
  )
);

// GPO Format 1 (template 80): AIP(2) + AFL(4) → SFI 1, record 1.
const gpoResponse = tlv("80", hexToBytes("0000" + "08010100"));

// Record with Track2 Equivalent Data + cardholder name.
const recordResponse = tlv(
  "70",
  concat(tlv("57", hexToBytes(TRACK2_HEX)), tlv("5F20", new TextEncoder().encode("CARD/HOLDER")))
);

const scriptedCard: Transceive = async (capdu) => {
  if (startsWith(capdu, "00A40400" + "0E")) return withSw(ppseResponse); // SELECT PPSE
  if (startsWith(capdu, "00A40400" + "07")) return withSw(new Uint8Array(0)); // SELECT AID (no PDOL)
  if (startsWith(capdu, "80A80000")) return withSw(gpoResponse); // GPO
  if (startsWith(capdu, "00B201" + "0C")) return withSw(recordResponse); // READ RECORD sfi1 rec1
  return hexToBytes("6A82"); // not found
};

describe("parseTrack2", () => {
  it("extracts PAN and expiry from Track2 Equivalent Data", () => {
    const r = parseTrack2(TRACK2_HEX);
    expect(r).not.toBeNull();
    expect(r!.pan).toBe("4111111111111111");
    expect(r!.expiryYYMM).toBe("2812");
  });

  it("returns null when there is no field separator", () => {
    expect(parseTrack2("4111111111111111")).toBeNull();
  });
});

describe("readEmvCard", () => {
  it("reads a synthetic Visa contactless card end to end", async () => {
    const card = await readEmvCard(scriptedCard);
    expect(card.pan).toBe("4111111111111111");
    expect(card.expiryYYMM).toBe("2812");
    expect(card.scheme).toBe("Visa");
    expect(card.aid).toBe(bytesToHex(VISA_AID));
    expect(card.cardholderName).toBe("CARD/HOLDER");
  });

  it("throws a helpful error when PPSE fails", async () => {
    const noCard: Transceive = async () => hexToBytes("6A82");
    await expect(readEmvCard(noCard)).rejects.toThrow(/PPSE/);
  });

  it("runs GENERATE AC and assembles field-55-equivalent emvData when the card has a CDOL1", async () => {
    // CDOL1: 9F02(6) 9F03(6) 9F1A(2) 95(5) 5F2A(2) 9A(3) 9C(1) 9F37(4) — a typical Visa CDOL1.
    const CDOL1_HEX = "9F0206" + "9F0306" + "9F1A02" + "9505" + "5F2A02" + "9A03" + "9C01" + "9F3704";
    const recordWithCdol1 = tlv("70", concat(tlv("57", hexToBytes(TRACK2_HEX)), tlv("8C", hexToBytes(CDOL1_HEX))));

    // GENERATE AC response, format 1 (primitive tag 80): CID(1) + ATC(2) + AC(8) + IAD(6).
    const gacValueHex = "80" + "0001" + "1122334455667788" + "060A03A09000";
    const gacResponse = tlv("80", hexToBytes(gacValueHex));

    const scriptedCardWithGac: Transceive = async (capdu) => {
      if (startsWith(capdu, "00A40400" + "0E")) return withSw(ppseResponse);
      if (startsWith(capdu, "00A40400" + "07")) return withSw(new Uint8Array(0));
      if (startsWith(capdu, "80A80000")) return withSw(gpoResponse);
      if (startsWith(capdu, "00B201" + "0C")) return withSw(recordWithCdol1);
      if (startsWith(capdu, "80AE8000")) return withSw(gacResponse); // GENERATE AC
      return hexToBytes("6A82");
    };

    const card = await readEmvCard(scriptedCardWithGac, 150000);
    expect(card.emvData).toBeDefined();

    const nodes = parseTlv(hexToBytes(card.emvData!));
    expect(bytesToHex(findTag(nodes, "9F26")!.value)).toBe("1122334455667788"); // the cryptogram itself
    expect(bytesToHex(findTag(nodes, "9F27")!.value)).toBe("80"); // CID
    expect(bytesToHex(findTag(nodes, "9F36")!.value)).toBe("0001"); // ATC
    expect(bytesToHex(findTag(nodes, "9F10")!.value)).toBe("060A03A09000"); // IAD
    expect(bytesToHex(findTag(nodes, "82")!.value)).toBe("0000"); // AIP, from the GPO fixture
    expect(bytesToHex(findTag(nodes, "84")!.value)).toBe(bytesToHex(VISA_AID));
    expect(bytesToHex(findTag(nodes, "9C")!.value)).toBe("00"); // transaction type = purchase
  });
});
