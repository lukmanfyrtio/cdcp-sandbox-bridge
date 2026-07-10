# cdcp-sandbox-bridge

Encrypted WebSocket relay between the **sandbox-reader** Android app (`edc-sdk/sandbox-reader`,
reads a **real contactless card** via the phone's internal NFC + its own EMV kernel) and the CDCP
sandbox web app.

```
Android phone (sandbox-reader app, reads card via internal NFC + own EMV kernel)
      │  WebSocket (:4001) as ?role=reader — card_read payload is AES-256-GCM
      │  encrypted by the phone itself before it ever reaches this bridge
      ▼
cdcp-sandbox-bridge   ── pure relay, never sees plaintext PAN/Track2/Field-55 for a real tap
      │  WebSocket (:4001) as ?role=web (default)
      ▼
cdcp-sandbox-web  (decrypts right before use, fills the card, runs the DUKPT + sale_trx flow)
```

The bridge no longer talks EMV/APDU or VPCD — that logic now lives in the phone's own EMV kernel
(edc-sdk). This is just a relay: it forwards `arm_tap` (amount) from the browser to the phone, and
`card_read` / `waiting_for_card` / `error` from the phone to the browser, keyed by the `role` query
param on the WebSocket connection.

## ⚠️ Real card data

This relays **real PANs** read by the phone. Only tap **your own test cards**. The PAN is masked in
the web UI and never persisted; still, treat this as a bench tool, not something to point at
customer cards.

## WebSocket encryption

The `card_read` event (PAN/Track2/Field-55) is AES-256-GCM encrypted by the phone itself before it
sends it — the bridge only relays the ciphertext, and the web app only decrypts it right at the
point it's about to build the `sale_trx` request. This matters because `bridgeUrl` can point
anywhere (see `wss://ws.lukman.site` default in the web app), not just `localhost`.

- Set `WS_ENCRYPT_KEY=<64 hex chars>` (32 bytes) in the environment on **both** sides that need to
  encrypt/decrypt: the phone (`sandbox-reader`'s `ws_enkrip_key` constant) and the web app
  (`DEFAULT_WS_ENCRYPT_KEY` — see `cdcp-sandbox-web/.env.example` / `docker-compose.yml`). The
  bridge only needs its own `WS_ENCRYPT_KEY` for the `/debug/simulate-card` fixture below — real
  taps pass through encrypted end-to-end and the bridge doesn't need the key for those at all.
- On startup, if `WS_ENCRYPT_KEY` isn't set, the bridge **generates a fresh key every run** (used
  only for `/debug/simulate-card`) and prints it to the console.
- Wrong or missing key on the web side → the tap fails with a decryption error, not a silent empty
  card — see `src/wsCrypto.ts` (bridge) / `cdcp-sandbox-web/src/crypto/wsCrypto.ts` (web).

## Run

### Docker Compose (from parent `cdcp-sandbox/`)

```
docker compose up --build       # WebSocket + HTTP on :4001
```

### Standalone

```
npm install
npm run dev      # WebSocket + HTTP on :4001
npm test         # wsCrypto encryption round-trip tests
```

## Phone setup

1. Build & install `sandbox-reader` from `edc-sdk` on an Android phone with NFC.
2. In the app, set the bridge WebSocket URL (defaults to `wss://ws.lukman.site`) and connect — it
   joins as `?role=reader`.
3. In the web app, expand **"Tap kartu asli pakai HP (NFC)"** → **Hubungkan** (joins as the default
   `?role=web`).
4. Arm an amount from the web app (or type it directly on the phone) and hold a contactless card
   **flat and still** against the phone for ~2–3 seconds.

## Debugging

- `GET /health` — liveness check.
- `POST /debug/simulate-card` (JSON `{pan, expiryYYMM, scheme}`) injects a fake, bridge-encrypted
  `card_read` to test the web integration without a phone/card — this is the one path where the
  bridge does still hold `WS_ENCRYPT_KEY` and encrypt on its own.
