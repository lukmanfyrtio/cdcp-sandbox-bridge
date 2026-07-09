// WebSocket hub: the web app connects here and receives card-read events as they happen.
import http from "http";
import { WebSocketServer, WebSocket } from "ws";
import { CardData } from "./emv";
import { encryptJson, EncryptedPayload } from "./wsCrypto";

export type BridgeEvent =
  | { type: "reader_connected" }
  | { type: "reader_disconnected" }
  | { type: "waiting_for_card" }
  | { type: "card_read"; card: CardData }
  | { type: "error"; message: string };

// What actually goes out on the wire for a card_read event — the card itself (PAN/Track2/Field-55)
// travels AES-256-GCM encrypted (wsCrypto.ts), since this hop otherwise carries it as cleartext
// JSON. Every other event type carries nothing sensitive and goes out unchanged.
type WireEvent = Exclude<BridgeEvent, { type: "card_read" }> | { type: "card_read"; cardEnc: EncryptedPayload };

export class WsHub {
  private wss: WebSocketServer;
  private clients = new Set<WebSocket>();
  private lastStatus: BridgeEvent = { type: "reader_disconnected" };
  // Amount the browser armed before the next tap — GENERATE AC needs the real amount to compute a
  // valid cryptogram, and the only way this bridge (which doesn't know about "amount" otherwise)
  // finds out is the client telling it right before the user taps. Defaults to 0 if never armed.
  private pendingAmount = 0;
  private readonly encryptionKey: Buffer;

  constructor(server: http.Server, encryptionKey: Buffer) {
    this.encryptionKey = encryptionKey;
    this.wss = new WebSocketServer({ server });
    this.wss.on("connection", (ws) => {
      this.clients.add(ws);
      // Greet the newcomer with the current reader status (never a card_read — see broadcast()).
      ws.send(JSON.stringify(this.toWire(this.lastStatus)));
      ws.on("close", () => this.clients.delete(ws));
      ws.on("error", () => this.clients.delete(ws));
      ws.on("message", (raw) => {
        try {
          const msg = JSON.parse(raw.toString());
          if (msg?.type === "arm_tap" && typeof msg.amount === "number") this.pendingAmount = msg.amount;
        } catch {
          /* ignore malformed client messages */
        }
      });
    });
  }

  takePendingAmount(): number {
    return this.pendingAmount;
  }

  private toWire(event: BridgeEvent): WireEvent {
    if (event.type !== "card_read") return event;
    return { type: "card_read", cardEnc: encryptJson(this.encryptionKey, event.card) };
  }

  broadcast(event: BridgeEvent): void {
    if (event.type !== "card_read") this.lastStatus = event;
    const payload = JSON.stringify(this.toWire(event));
    for (const ws of this.clients) {
      if (ws.readyState === WebSocket.OPEN) ws.send(payload);
    }
  }
}
