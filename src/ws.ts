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

  constructor(server: http.Server) {
    this.wss = new WebSocketServer({ server });
    this.wss.on("connection", (ws) => {
      this.clients.add(ws);
      // Greet the newcomer with the current reader status.
      ws.send(JSON.stringify(this.lastStatus));
      ws.on("close", () => this.clients.delete(ws));
      ws.on("error", () => this.clients.delete(ws));
    });
  }

  broadcast(event: BridgeEvent): void {
    if (event.type !== "card_read") this.lastStatus = event;
    const payload = JSON.stringify(event);
    for (const ws of this.clients) {
      if (ws.readyState === WebSocket.OPEN) ws.send(payload);
    }
  }
}
