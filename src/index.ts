// cdcp-sandbox-bridge bootstrap.
//   - VPCD TCP server (default 35963): the Android vsmartcard "Remote Smart Card Reader" connects here.
//   - WebSocket + HTTP server (default 4001): the web app subscribes to card-read events here.
//   - Debug endpoint POST /debug/simulate-card: inject a fake card read (for hardware-free testing).
import http from "http";
import { CardData, readEmvCard } from "./emv";
import { bytesToHex } from "./hex";
import { createVpcdServer, VpcdConnection } from "./vpcd";
import { WsHub } from "./ws";
import { loadOrGenerateKey } from "./wsCrypto";

const VPCD_PORT = Number(process.env.VPCD_PORT) || 35963;
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
      let card: CardData = { pan: "4111111111111111", expiryYYMM: "2812", scheme: "Visa", cardholderName: "SANDBOX/TEST" };
      try {
        if (body.trim()) card = { ...card, ...JSON.parse(body) };
      } catch {
        /* ignore, use default */
      }
      hub.broadcast({ type: "card_read", card });
      res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ ok: true, card }));
    });
    return;
  }
  res.writeHead(404).end();
});

const hub = new WsHub(httpServer, wsEncryptionKey);
httpServer.listen(WS_PORT, () => console.log(`WebSocket + debug HTTP on http://localhost:${WS_PORT}`));

/** Poll the connected reader for a card, read it when present, then wait for it to leave. */
async function driveReader(conn: VpcdConnection): Promise<void> {
  conn.powerOn();
  let cardPresent = false;
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  while (true) {
    let atr: Uint8Array;
    try {
      atr = await conn.requestAtr();
    } catch {
      return; // connection gone
    }

    if (atr.length > 0 && !cardPresent) {
      cardPresent = true;
      console.log(`Card in field, ATR=${bytesToHex(atr)}`);
      // Verbose APDU tracing so real-card read issues are diagnosable from the console.
      const tracedTransceive = async (capdu: Uint8Array) => {
        console.log(`  → ${bytesToHex(capdu)}`);
        const rapdu = await conn.transceive(capdu);
        console.log(`  ← ${bytesToHex(rapdu)}`);
        return rapdu;
      };
      try {
        const amount = hub.takePendingAmount();
        const card = await readEmvCard(tracedTransceive, amount, (m) => console.log("  " + m));
        // Full dump of everything extracted from this card — masked PAN only, everything else as-is.
        console.log("Read result:", {
          ...card,
          pan: `${card.pan.slice(0, 6)}${"*".repeat(Math.max(0, card.pan.length - 10))}${card.pan.slice(-4)}`,
        });
        hub.broadcast({ type: "card_read", card });
      } catch (e: any) {
        const message = e?.message ?? String(e);
        console.warn("Read failed:", message);
        hub.broadcast({ type: "error", message });
      }
    } else if (atr.length === 0 && cardPresent) {
      cardPresent = false;
      hub.broadcast({ type: "waiting_for_card" });
    }
    await sleep(400);
  }
}

const vpcdServer = createVpcdServer((conn) => {
  console.log("Reader connected");
  hub.broadcast({ type: "reader_connected" });
  hub.broadcast({ type: "waiting_for_card" });

  conn.on("close", () => {
    console.log("Reader disconnected");
    hub.broadcast({ type: "reader_disconnected" });
  });
  conn.on("error", (e) => console.warn("Reader socket error:", e?.message ?? e));

  driveReader(conn).catch((e) => console.warn("driveReader ended:", e?.message ?? e));
});

vpcdServer.listen(VPCD_PORT, () => {
  console.log(`VPCD reader server on tcp://0.0.0.0:${VPCD_PORT}`);
  console.log(`  In the Android 'Remote Smart Card Reader' app, connect to  <this-PC-IP>:${VPCD_PORT}`);
});
