// cdcp-sandbox-bridge bootstrap.
//   - WebSocket + HTTP server (default 4001): the sandbox-reader Android app connects here as
//     `?role=reader` (it reads cards itself over internal NFC and sends already-encrypted
//     card_read events); the web app connects as `?role=web` (default) and subscribes to them.
//   - Debug endpoint POST /debug/simulate-card: inject a fake card read (for hardware-free testing).
import http from "http";
import { CardData } from "./ws";
import { WsHub } from "./ws";
import { loadOrGenerateKey } from "./wsCrypto";

const WS_PORT = Number(process.env.WS_PORT) || 4001;
const wsEncryptionKey = loadOrGenerateKey(process.env.WS_ENCRYPT_KEY);

const httpServer = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  if (req.method === "OPTIONS") {
    res.writeHead(204).end();
    return;
  }
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ ok: true }));
    return;
  }
  // Debug: simulate a card tap so the web integration can be tested without a phone/card.
  if (req.method === "POST" && req.url === "/debug/simulate-card") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      let card: CardData = {
        amount: 0,
        cardModeType: "RF",
        pan: "4111111111111111",
        trackData: { track2Data: "4111111111111111D2812101000000000000" },
        isPinBlock: true,
      };
      try {
        if (body.trim()) card = { ...card, ...JSON.parse(body) };
      } catch {
        /* ignore, use default */
      }
      hub.broadcastDebugCardRead(card);
      res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ ok: true, card }));
    });
    return;
  }
  res.writeHead(404).end();
});

const hub = new WsHub(httpServer, wsEncryptionKey);
httpServer.listen(WS_PORT, () => {
  console.log(`WebSocket + debug HTTP on http://localhost:${WS_PORT}`);
  console.log(`  sandbox-reader connects as ws://<host>:${WS_PORT}/?role=reader`);
  console.log(`  web app connects as ws://<host>:${WS_PORT}/  (defaults to role=web)`);
});
