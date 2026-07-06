// WebSocket hub: the web app connects here and receives card-read events as they happen.
import http from "http";
import { WebSocketServer, WebSocket } from "ws";
import { CardData } from "./emv";

export type BridgeEvent =
  | { type: "reader_connected" }
  | { type: "reader_disconnected" }
  | { type: "waiting_for_card" }
  | { type: "card_read"; card: CardData }
  | { type: "error"; message: string };

export class WsHub {
  private wss: WebSocketServer;
  private clients = new Set<WebSocket>();
  private lastStatus: BridgeEvent = { type: "reader_disconnected" };
  // Amount the browser armed before the next tap — GENERATE AC needs the real amount to compute a
  // valid cryptogram, and the only way this bridge (which doesn't know about "amount" otherwise)
  // finds out is the client telling it right before the user taps. Defaults to 0 if never armed.
  private pendingAmount = 0;

  constructor(server: http.Server) {
    this.wss = new WebSocketServer({ server });
    this.wss.on("connection", (ws) => {
      this.clients.add(ws);
      // Greet the newcomer with the current reader status.
      ws.send(JSON.stringify(this.lastStatus));
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

  broadcast(event: BridgeEvent): void {
    if (event.type !== "card_read") this.lastStatus = event;
    const payload = JSON.stringify(event);
    for (const ws of this.clients) {
      if (ws.readyState === WebSocket.OPEN) ws.send(payload);
    }
  }
}
