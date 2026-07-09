import { readFileSync } from "fs";
import { join } from "path";
import { describe, expect, it } from "vitest";
import { hexToBytes } from "../src/hex";
import { CapkJsonEntry, caKeyTableFromJson } from "../src/oda";

describe("caKeyTableFromJson", () => {
  it("loads the generated sandbox CAPK fixture (src/tools/generateTestCapk.ts's output) correctly", () => {
    const raw = readFileSync(join(__dirname, "..", "test-fixtures", "sandbox-capks.format.json"), "utf8");
    const entries: CapkJsonEntry[] = JSON.parse(raw);
    expect(entries.length).toBeGreaterThan(0);

    const table = caKeyTableFromJson(entries);
    const entry = entries[0];
    const found = table.find(entry.RID, parseInt(entry.CAPKIndex, 16));

    expect(found).not.toBeNull();
    expect(found!.rid).toBe(entry.RID);
    expect(found!.modulus).toEqual(hexToBytes(entry.CAPKModulus));
    expect(found!.exponent).toEqual(hexToBytes(entry.CAPKExponent));
  });

  it("returns null for an RID/index not present in the table", () => {
    const table = caKeyTableFromJson([
      { RID: "F0000000AA", CAPKIndex: "01", CAPKModulus: "AABB", CAPKExponent: "03" },
    ]);
    expect(table.find("F0000000AA", 0x02)).toBeNull();
    expect(table.find("A000000003", 0x01)).toBeNull();
  });
});
