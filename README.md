# cdcp-sandbox-bridge

Bridges an Android phone running **vsmartcard "Remote Smart Card Reader"** to the CDCP sandbox web app,
so you can tap a **real contactless card** and have its data flow into the simulator.

```
Android phone (Remote Smart Card Reader app, taps card)
      │  VPCD protocol over TCP (:35963)
      ▼
cdcp-sandbox-bridge   ── reads EMV: SELECT PPSE → SELECT AID → GPO → READ RECORD → parse Track2/PAN
      │  WebSocket (:4001) — card_read payload is AES-256-GCM encrypted, see below
      ▼
cdcp-sandbox-web  (decrypts right before use, fills the card, runs the DUKPT + sale_trx flow)
```

## ⚠️ Real card data

This reads **real PANs** from real cards. Only tap **your own test cards**. The PAN is masked in the web
UI and never persisted; still, treat this as a bench tool, not something to point at customer cards.

## WebSocket encryption

The `card_read` event (PAN/Track2/Field-55) is encrypted (AES-256-GCM) before it goes out over the
WebSocket — the web app only decrypts it right at the point it's about to build the `sale_trx`
request, not on arrival. This matters because `bridgeUrl` can point anywhere (see
`wss://ws.lukman.site` default in the web app), not just `localhost`.

- On startup, if `WS_ENCRYPT_KEY` isn't set, the bridge **generates a fresh key every run** and
  prints it to the console — paste that into the web app's **"WS Encryption Key (hex)"** field.
- Set `WS_ENCRYPT_KEY=<64 hex chars>` (32 bytes) in the environment to keep the same key across
  restarts, so you don't have to re-paste it every time.
- Wrong or missing key on the web side → the tap fails with a decryption error, not a silent empty
  card — see `src/wsCrypto.ts` (bridge) / `cdcp-sandbox-web/src/crypto/wsCrypto.ts` (web).

## Run

### Docker Compose (from parent `cdcp-sandbox/`)

```
docker compose up --build       # bridge VPCD on :35963, WebSocket on :4001
```

### Standalone

```
npm install
npm run dev      # VPCD :35963, WebSocket + HTTP :4001
npm test         # VPCD framing + EMV/Track2 parsing tests
```

## Phone setup

1. Install **Remote Smart Card Reader** from F-Droid on an Android phone with NFC.
2. In the app, set Host = your PC's LAN IP, Port = `35963`, and Connect.
3. On the same PC, make sure inbound TCP `35963` is allowed through the firewall.
4. In the web app, expand **"Tap kartu asli pakai HP (NFC)"** → **Hubungkan** (`ws://localhost:4001`).
5. Hold a contactless card **flat and still** against the phone for ~2–3 seconds.

**Tip:** the app's tag timeout is short (~500 ms). If you see `Tag was lost` / `VPCD response timeout`,
the card moved before the ~6 APDU round-trips finished — hold it steady.

## Debugging

- The bridge logs every APDU (`→` command, `←` response) plus `Read PAN 4xxxxx****xxxx`.
- `POST /debug/simulate-card` (JSON `{pan, expiryYYMM, scheme}`) injects a fake card read to test the
  web integration without hardware.
- GPO/PDOL handling in `src/apdu.ts` uses sensible terminal defaults; some card schemes may need small
  tweaks there (TTQ `9F66`, amounts, country/currency).
