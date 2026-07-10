// WebSocket hub: a thin encrypted relay between two kinds of client —
//   - "reader" (the sandbox-reader Android app, which now does the EMV read itself over internal
//     NFC and already AES-256-GCM-encrypts the card_read payload before it ever reaches us)
//   - "web" (the browser), same as before
// Role is picked via the `?role=reader` query string on the WS URL; anything else (or missing)
// defaults to "web" so the existing browser client needs no change. The bridge itself never sees
// plaintext card data for real taps — it only relays the already-encrypted `cardEnc` blob — except
// for the /debug/simulate-card fixture in index.ts, which still needs the key to fabricate one.
import http from "http";
import { URL } from "url";
import { WebSocketServer, WebSocket } from "ws";
import { encryptJson, EncryptedPayload } from "./wsCrypto";

// Same shape as sandbox-reader's com.lib.core.emv.CardData (Gson-serialized as-is, see
// sandbox-reader/src/main/java/com/cashlez/sandboxreader/ws/WsBridgeClient.kt) — the bridge relays
// this verbatim (still encrypted) for real taps, so it never needs to know this shape itself except
// for the /debug/simulate-card fixture below, which fabricates one to match.
export interface TrackData {
  track1Data?: string | null;
  track2Data?: string | null;
  track3Data?: string | null;
}

export interface CardData {
  amount?: number;
  cardModeType?: "IC" | "MAG" | "RF" | null;
  pan?: string | null;
  trackData?: TrackData | null;
  iccData?: string | null;
  pinBlock?: string | null;
  isPinBlock?: boolean;
}

export type BridgeEvent =
  | { type: "reader_connected" }
  | { type: "reader_disconnected" }
  | { type: "waiting_for_card" }
  | { type: "card_read"; card: CardData }
  | { type: "error"; message: string };

// What actually goes out on the wire for a card_read event — the card itself (PAN/Track2/Field-55)
// travels AES-256-GCM encrypted. For real taps the reader already sends it pre-encrypted (relayed
// verbatim); only the /debug/simulate-card fixture needs this bridge to encrypt on its behalf.
type WireEvent = Exclude<BridgeEvent, { type: "card_read" }> | { type: "card_read"; cardEnc: EncryptedPayload };

type Role = "reader" | "web";

function roleFromUrl(url: string | undefined): Role {
  try {
    const parsed = new URL(url ?? "", "http://localhost");
    return parsed.searchParams.get("role") === "reader" ? "reader" : "web";
  } catch {
    return "web";
  }
}

export class WsHub {
  private wss: WebSocketServer;
  private readers = new Set<WebSocket>();
  private webs = new Set<WebSocket>();
  private lastStatus: BridgeEvent = { type: "reader_disconnected" };
  private readonly encryptionKey: Buffer;

  constructor(server: http.Server, encryptionKey: Buffer) {
    this.encryptionKey = encryptionKey;
    this.wss = new WebSocketServer({ server });
    this.wss.on("connection", (ws, req) => {
      const role = roleFromUrl(req.url);
      if (role === "reader") this.handleReader(ws);
      else this.handleWeb(ws);
    });
  }

  private handleReader(ws: WebSocket): void {
    this.readers.add(ws);
    this.setStatus({ type: "reader_connected" });
    this.setStatus({ type: "waiting_for_card" });
    // Deliberately no eager arm_tap here: a reader that just connected has no business inheriting
    // whatever amount some unrelated web session armed at any point since this bridge process last
    // restarted (was a real bug — a stale amount from hours/sessions ago got replayed to a phone
    // that had never even opened the web app). The web app already re-sends arm_tap on its own
    // reconnect when a tap is genuinely in flight (see sandboxContext.tsx's awaitingTapRef), so
    // this bridge doesn't need to remember/replay anything.

    ws.on("close", () => {
      this.readers.delete(ws);
      this.setStatus({ type: "reader_disconnected" });
    });
    ws.on("error", () => this.readers.delete(ws));
    ws.on("message", (raw) => {
      let msg: any;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        return; // ignore malformed reader messages
      }
      // The reader already carries card_read pre-encrypted (`cardEnc`) — relay as-is, we never see
      // plaintext PAN/Track2/Field-55 for a real tap.
      if (msg?.type === "waiting_for_card" || msg?.type === "error" || (msg?.type === "card_read" && msg.cardEnc)) {
        if (msg.type !== "card_read") this.lastStatus = msg;
        this.sendToWebs(msg);
      }
    });
  }

  private handleWeb(ws: WebSocket): void {
    this.webs.add(ws);
    ws.send(JSON.stringify(this.lastStatus));
    ws.on("close", () => this.webs.delete(ws));
    ws.on("error", () => this.webs.delete(ws));
    ws.on("message", (raw) => {
      try {
        const msg = JSON.parse(raw.toString());
        if (msg?.type === "arm_tap" && typeof msg.amount === "number") {
          this.sendToReaders({ type: "arm_tap", amount: msg.amount });
        }
      } catch {
        /* ignore malformed client messages */
      }
    });
  }

  private setStatus(event: BridgeEvent): void {
    this.lastStatus = event;
    this.sendToWebs(event);
  }

  /** Fabricate + broadcast an encrypted card_read — used only by /debug/simulate-card. */
  broadcastDebugCardRead(card: CardData): void {
    const wire: WireEvent = { type: "card_read", cardEnc: encryptJson(this.encryptionKey, card) };
    this.sendToWebs(wire);
  }

  private sendToWebs(payload: unknown): void {
    const data = JSON.stringify(payload);
    for (const ws of this.webs) {
      if (ws.readyState === WebSocket.OPEN) ws.send(data);
    }
  }

  private sendToReaders(payload: unknown): void {
    const data = JSON.stringify(payload);
    for (const ws of this.readers) {
      if (ws.readyState === WebSocket.OPEN) ws.send(data);
    }
  }
}
