// Offline Data Authentication (SDA/DDA/CDA) scaffold — deliberately NOT implemented. Real
// verification needs a CA public key per scheme/RID, licensed from the scheme under EMVCo Level 2
// certification; without one, "verifying" a signature would be false confidence, not security.
// This exists so a real key table can be dropped in later without touching call sites.
import { TlvNode } from "./tlv";

export interface CaPublicKey {
  rid: string;
  index: number;
  modulus: Uint8Array;
  exponent: Uint8Array;
}

export interface CaKeyTable {
  find(rid: string, index: number): CaPublicKey | null;
}

export const emptyCaKeyTable: CaKeyTable = { find: () => null };

export interface OdaResult {
  performed: boolean;
  method?: "SDA" | "DDA" | "CDA";
}

export function performOda(_recordsTlv: TlvNode[], _caKeys: CaKeyTable = emptyCaKeyTable): OdaResult {
  return { performed: false };
}
