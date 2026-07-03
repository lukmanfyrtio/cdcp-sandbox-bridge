// VPCD protocol (vsmartcard "virtual PC/SC" protocol). We act as the vpcd side: we LISTEN, the
// Android "Remote Smart Card Reader" app connects to us, and we drive it — sending control bytes
// and command APDUs, receiving ATRs and response APDUs relayed from the physical card via NFC.
//
// Wire format: each message is a 2-byte big-endian length prefix followed by that many payload bytes.
// A payload of length 1 is a control byte; longer payloads are APDUs.
import net from "net";
import { EventEmitter } from "events";

export const VPCD_CTRL_OFF = 0x00;
export const VPCD_CTRL_ON = 0x01;
export const VPCD_CTRL_RESET = 0x02;
export const VPCD_CTRL_ATR = 0x04;

export function encodeMessage(payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(2 + payload.length);
  out[0] = (payload.length >> 8) & 0xff;
  out[1] = payload.length & 0xff;
  out.set(payload, 2);
  return out;
}

/** Incrementally splits a byte stream into length-prefixed payloads. */
export class VpcdFramer {
  private buffer = Buffer.alloc(0);

  push(chunk: Buffer): Uint8Array[] {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    const messages: Uint8Array[] = [];
    while (this.buffer.length >= 2) {
      const len = this.buffer.readUInt16BE(0);
      if (this.buffer.length < 2 + len) break;
      messages.push(new Uint8Array(this.buffer.subarray(2, 2 + len)));
      this.buffer = this.buffer.subarray(2 + len);
    }
    return messages;
  }
}

/**
 * Wraps a single connected reader socket. Exposes an async transceive() that sends a command APDU
 * and resolves with the response APDU. Also emits "atr" when a card is powered on.
 */
export class VpcdConnection extends EventEmitter {
  private framer = new VpcdFramer();
  private pendingResolvers: ((msg: Uint8Array) => void)[] = [];

  constructor(private socket: net.Socket) {
    super();
    socket.on("data", (chunk) => {
      for (const msg of this.framer.push(chunk)) this.handleMessage(msg);
    });
    socket.on("close", () => this.emit("close"));
    socket.on("error", (e) => this.emit("error", e));
  }

  private handleMessage(msg: Uint8Array) {
    const resolver = this.pendingResolvers.shift();
    if (resolver) resolver(msg);
    else this.emit("unsolicited", msg);
  }

  private send(payload: Uint8Array): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this.pendingResolvers.indexOf(wrapped);
        if (idx >= 0) this.pendingResolvers.splice(idx, 1);
        reject(new Error("VPCD response timeout"));
      }, 8000);
      const wrapped = (msg: Uint8Array) => {
        clearTimeout(timer);
        resolve(msg);
      };
      this.pendingResolvers.push(wrapped);
      this.socket.write(encodeMessage(payload));
    });
  }

  private sendControl(ctrl: number): void {
    this.socket.write(encodeMessage(Uint8Array.of(ctrl)));
  }

  powerOn(): void {
    this.sendControl(VPCD_CTRL_ON);
  }
  powerOff(): void {
    this.sendControl(VPCD_CTRL_OFF);
  }
  reset(): void {
    this.sendControl(VPCD_CTRL_RESET);
  }

  /** Request the ATR. Returns the ATR bytes (empty if no card is currently in the field). */
  async requestAtr(): Promise<Uint8Array> {
    return this.send(Uint8Array.of(VPCD_CTRL_ATR));
  }

  /** Send a command APDU, resolve with the response APDU (data + SW1 SW2). */
  async transceive(capdu: Uint8Array): Promise<Uint8Array> {
    return this.send(capdu);
  }

  end(): void {
    this.socket.end();
  }
}

export interface VpcdServerEvents {
  connection: (conn: VpcdConnection) => void;
}

export function createVpcdServer(onConnection: (conn: VpcdConnection) => void): net.Server {
  return net.createServer((socket) => {
    socket.setNoDelay(true);
    onConnection(new VpcdConnection(socket));
  });
}
