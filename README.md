# cdcp-sandbox-bridge

Bridges an Android phone running **vsmartcard "Remote Smart Card Reader"** to the CDCP sandbox web app,
so you can tap a **real contactless card** and have its data flow into the simulator.

```
Android phone (Remote Smart Card Reader app, taps card)
      │  VPCD protocol over TCP (:35963)
      ▼
cdcp-sandbox-bridge   ── reads EMV: SELECT PPSE → SELECT AID → GPO → READ RECORD → parse Track2/PAN
      │  WebSocket (:4001)
      ▼
cdcp-sandbox-web  (listens, fills the card, runs the existing DUKPT + sale_trx flow)
```

## ⚠️ Real card data

This reads **real PANs** from real cards. Only tap **your own test cards**. The PAN is masked in the web
UI and never persisted; still, treat this as a bench tool, not something to point at customer cards.

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
