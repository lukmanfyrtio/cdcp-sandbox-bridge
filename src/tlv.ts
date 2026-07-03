// Minimal BER-TLV parser for EMV data. Handles multi-byte tags and multi-byte lengths,
// and recursively parses constructed (template) objects.
import { bytesToHex } from "./hex";

export interface TlvNode {
  tag: string; // uppercase hex, e.g. "6F", "9F38"
  length: number;
  value: Uint8Array;
  children: TlvNode[];
}

function isConstructed(firstTagByte: number): boolean {
  return (firstTagByte & 0x20) !== 0;
}

export function parseTlv(data: Uint8Array): TlvNode[] {
  const nodes: TlvNode[] = [];
  let i = 0;
  while (i < data.length) {
    // Skip 0x00 / 0xFF padding between objects.
    if (data[i] === 0x00 || data[i] === 0xff) {
      i++;
      continue;
    }

    const tagStart = i;
    let tagByte = data[i++];
    // Multi-byte tag: low 5 bits all set → subsequent bytes while high bit (0x80) set.
    if ((tagByte & 0x1f) === 0x1f) {
      while (i < data.length && (data[i] & 0x80) !== 0) i++;
      i++; // consume the last tag byte (high bit clear)
    }
    const tag = bytesToHex(data.slice(tagStart, i));

    if (i >= data.length) break;

    // Length
    let length = data[i++];
    if (length & 0x80) {
      const numBytes = length & 0x7f;
      length = 0;
      for (let k = 0; k < numBytes; k++) length = (length << 8) | data[i++];
    }

    const value = data.slice(i, i + length);
    i += length;

    const node: TlvNode = { tag, length, value, children: [] };
    if (isConstructed(tagByte)) {
      node.children = parseTlv(value);
    }
    nodes.push(node);
  }
  return nodes;
}

/** Depth-first search for the first node with the given tag (uppercase hex). */
export function findTag(nodes: TlvNode[], tag: string): TlvNode | null {
  const target = tag.toUpperCase();
  for (const n of nodes) {
    if (n.tag === target) return n;
    if (n.children.length) {
      const hit = findTag(n.children, target);
      if (hit) return hit;
    }
  }
  return null;
}

/** Collect all nodes with the given tag across the tree. */
export function findAllTags(nodes: TlvNode[], tag: string): TlvNode[] {
  const target = tag.toUpperCase();
  const out: TlvNode[] = [];
  const walk = (list: TlvNode[]) => {
    for (const n of list) {
      if (n.tag === target) out.push(n);
      if (n.children.length) walk(n.children);
    }
  };
  walk(nodes);
  return out;
}
