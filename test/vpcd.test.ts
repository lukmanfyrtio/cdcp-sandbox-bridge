import { describe, expect, it } from "vitest";
import { encodeMessage, VpcdFramer } from "../src/vpcd";
import { bytesToHex } from "../src/hex";

describe("VPCD framing", () => {
  it("encodes a payload with a 2-byte big-endian length prefix", () => {
    expect(bytesToHex(encodeMessage(Uint8Array.of(0x04)))).toBe("000104");
    expect(bytesToHex(encodeMessage(Uint8Array.of(0x00, 0xa4, 0x04, 0x00)))).toBe("000400A40400");
  });

  it("splits a stream into messages, buffering partial frames", () => {
    const framer = new VpcdFramer();
    // Two messages: [04] and [00 A4], delivered across chunk boundaries.
    const full = Buffer.from("000104" + "000200A4", "hex");
    const first = framer.push(full.subarray(0, 2)); // only length prefix of msg 1
    expect(first).toHaveLength(0);
    const rest = framer.push(full.subarray(2)); // remainder
    expect(rest.map((m) => bytesToHex(m))).toEqual(["04", "00A4"]);
  });

  it("handles multiple whole messages in one chunk", () => {
    const framer = new VpcdFramer();
    const out = framer.push(Buffer.from("000101" + "000104", "hex"));
    expect(out.map((m) => bytesToHex(m))).toEqual(["01", "04"]);
  });
});
