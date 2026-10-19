/**
 * Authenticated Encryption with Associated Data (AEAD) & 64-bit Anti-Replay
 *
 * Implements:
 * - RFC 8439 ChaCha20 Stream Cipher & Poly1305 Authenticator
 * - RFC 4303 64-bit Sliding Anti-Replay Window for Tactical COMSEC
 * - STANAG 5516 / Tactical Data Link Packet Framer & Cryptographic Dissector
 */

function rotl32(v: number, n: number): number {
  return ((v << n) | (v >>> (32 - n))) >>> 0;
}

// ============================================================================
// ChaCha20 Stream Cipher (RFC 8439)
// ============================================================================

export class ChaCha20 {
  public static quarterRound(state: Uint32Array, a: number, b: number, c: number, d: number): void {
    state[a] = (state[a] + state[b]) >>> 0;
    state[d] = rotl32(state[d] ^ state[a], 16);
    state[c] = (state[c] + state[d]) >>> 0;
    state[b] = rotl32(state[b] ^ state[c], 12);
    state[a] = (state[a] + state[b]) >>> 0;
    state[d] = rotl32(state[d] ^ state[a], 8);
    state[c] = (state[c] + state[d]) >>> 0;
    state[b] = rotl32(state[b] ^ state[c], 7);
  }

  public static block(key: Uint8Array, counter: number, nonce: Uint8Array): Uint8Array {
    if (key.length !== 32) throw new Error('ChaCha20 key must be 32 bytes');
    if (nonce.length !== 12) throw new Error('ChaCha20 nonce must be 12 bytes');

    const state = new Uint32Array(16);
    // Constants "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    const keyView = new DataView(key.buffer, key.byteOffset, 32);
    for (let i = 0; i < 8; i++) {
      state[4 + i] = keyView.getUint32(i * 4, true);
    }

    state[12] = counter >>> 0;

    const nonceView = new DataView(nonce.buffer, nonce.byteOffset, 12);
    state[13] = nonceView.getUint32(0, true);
    state[14] = nonceView.getUint32(4, true);
    state[15] = nonceView.getUint32(8, true);

    const working = new Uint32Array(state);

    for (let i = 0; i < 10; i++) {
      // Column round
      this.quarterRound(working, 0, 4, 8, 12);
      this.quarterRound(working, 1, 5, 9, 13);
      this.quarterRound(working, 2, 6, 10, 14);
      this.quarterRound(working, 3, 7, 11, 15);
      // Diagonal round
      this.quarterRound(working, 0, 5, 10, 15);
      this.quarterRound(working, 1, 6, 11, 12);
      this.quarterRound(working, 2, 7, 8, 13);
      this.quarterRound(working, 3, 4, 9, 14);
    }

    const output = new Uint8Array(64);
    const outView = new DataView(output.buffer, output.byteOffset, 64);
    for (let i = 0; i < 16; i++) {
      outView.setUint32(i * 4, (working[i] + state[i]) >>> 0, true);
    }
    return output;
  }

  public static xorStream(
    input: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array,
    initialCounter = 1
  ): Uint8Array {
    const out = new Uint8Array(input.length);
    let counter = initialCounter;
    let offset = 0;

    while (offset < input.length) {
      const keystream = this.block(key, counter++, nonce);
      const take = Math.min(64, input.length - offset);
      for (let i = 0; i < take; i++) {
        out[offset + i] = input[offset + i] ^ keystream[i];
      }
      offset += take;
    }
    return out;
  }
}

// ============================================================================
// Poly1305 One-Time Authenticator (RFC 8439)
// ============================================================================

export class Poly1305 {
  public static authenticate(msg: Uint8Array, key: Uint8Array): Uint8Array {
    if (key.length !== 32) throw new Error('Poly1305 key must be 32 bytes');

    // Clamp r: r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    const r0 = (key[0] | (key[1] << 8) | (key[2] << 16) | (key[3] << 24)) & 0x0fffffff;
    const r1 = (key[4] | (key[5] << 8) | (key[6] << 16) | (key[7] << 24)) & 0x0ffffffc;
    const r2 = (key[8] | (key[9] << 8) | (key[10] << 16) | (key[11] << 24)) & 0x0ffffffc;
    const r3 = (key[12] | (key[13] << 8) | (key[14] << 16) | (key[15] << 24)) & 0x0ffffffc;

    const rBig = BigInt(r0) | (BigInt(r1) << 32n) | (BigInt(r2) << 64n) | (BigInt(r3) << 96n);

    // s
    const s0 = key[16] | (key[17] << 8) | (key[18] << 16) | (key[19] << 24);
    const s1 = key[20] | (key[21] << 8) | (key[22] << 16) | (key[23] << 24);
    const s2 = key[24] | (key[25] << 8) | (key[26] << 16) | (key[27] << 24);
    const s3 = key[28] | (key[29] << 8) | (key[30] << 16) | (key[31] << 24);
    const sBig =
      BigInt(s0 >>> 0) |
      (BigInt(s1 >>> 0) << 32n) |
      (BigInt(s2 >>> 0) << 64n) |
      (BigInt(s3 >>> 0) << 96n);

    const P = (1n << 130n) - 5n;
    let acc = 0n;

    let offset = 0;
    while (offset < msg.length) {
      const take = Math.min(16, msg.length - offset);
      let n = 0n;
      for (let i = 0; i < take; i++) {
        n |= BigInt(msg[offset + i]) << BigInt(8 * i);
      }
      n |= 1n << BigInt(8 * take); // Append 1 bit after block

      acc = ((acc + n) * rBig) % P;
      offset += take;
    }

    acc = (acc + sBig) % (1n << 128n);

    const tag = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      tag[i] = Number((acc >> BigInt(8 * i)) & 0xffn);
    }
    return tag;
  }
}

// ============================================================================
// ChaCha20-Poly1305 AEAD Engine
// ============================================================================

export class ChaCha20Poly1305AEAD {
  public static seal(
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    associatedData: Uint8Array
  ): { ciphertext: Uint8Array; tag: Uint8Array } {
    // Generate Poly1305 one-time key with block counter 0
    const otkBlock = ChaCha20.block(key, 0, nonce);
    const polyKey = otkBlock.subarray(0, 32);

    // Encrypt plaintext with counter starting at 1
    const ciphertext = ChaCha20.xorStream(plaintext, key, nonce, 1);

    // Build MAC input: AAD || pad16 || Ciphertext || pad16 || len(AAD) || len(CT)
    const macData = this.buildMacInput(associatedData, ciphertext);
    const tag = Poly1305.authenticate(macData, polyKey);

    return { ciphertext, tag };
  }

  public static open(
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    associatedData: Uint8Array,
    tag: Uint8Array
  ): Uint8Array | null {
    if (tag.length !== 16) return null;

    const otkBlock = ChaCha20.block(key, 0, nonce);
    const polyKey = otkBlock.subarray(0, 32);

    const macData = this.buildMacInput(associatedData, ciphertext);
    const computedTag = Poly1305.authenticate(macData, polyKey);

    let diff = 0;
    for (let i = 0; i < 16; i++) {
      diff |= tag[i] ^ computedTag[i];
    }
    if (diff !== 0) return null; // Authentication failed

    return ChaCha20.xorStream(ciphertext, key, nonce, 1);
  }

  private static buildMacInput(aad: Uint8Array, ct: Uint8Array): Uint8Array {
    const padAad = (16 - (aad.length % 16)) % 16;
    const padCt = (16 - (ct.length % 16)) % 16;
    const total = aad.length + padAad + ct.length + padCt + 16;

    const buf = new Uint8Array(total);
    buf.set(aad, 0);
    buf.set(ct, aad.length + padAad);

    const view = new DataView(buf.buffer, buf.byteOffset + total - 16, 16);
    view.setBigUint64(0, BigInt(aad.length), true);
    view.setBigUint64(8, BigInt(ct.length), true);
    return buf;
  }
}

// ============================================================================
// 64-bit Sliding Anti-Replay Window (RFC 4303)
// ============================================================================

export class AntiReplayWindow {
  private highestSeq = 0n;
  private bitmap = 0n;
  private readonly windowSize = 64n;

  public reset(): void {
    this.highestSeq = 0n;
    this.bitmap = 0n;
  }

  public checkAndAdvance(seq: bigint): { valid: boolean; reason?: string } {
    if (seq <= 0n) {
      return { valid: false, reason: 'Sequence number must be strictly positive' };
    }

    if (seq > this.highestSeq) {
      const diff = seq - this.highestSeq;
      if (diff < this.windowSize) {
        this.bitmap = (this.bitmap << diff) | 1n;
      } else {
        this.bitmap = 1n;
      }
      this.highestSeq = seq;
      return { valid: true };
    }

    const diff = this.highestSeq - seq;
    if (diff >= this.windowSize) {
      return { valid: false, reason: `Packet sequence ${seq} is too old (window expired)` };
    }

    const mask = 1n << diff;
    if ((this.bitmap & mask) !== 0n) {
      return { valid: false, reason: `Replay attack detected: sequence ${seq} already processed` };
    }

    this.bitmap |= mask;
    return { valid: true };
  }

  public getHighestSequence(): bigint {
    return this.highestSeq;
  }

  public getBitmap(): bigint {
    return this.bitmap;
  }
}

// ============================================================================
// STANAG 5516 Tactical Data Link Packet Framer
// ============================================================================

export interface TacticalPacketHeader {
  magic: number; // 0x5153 ("QS")
  version: number; // 0x02
  msgType: number; // 0x02 = J2.2 PPLI, 0x03 = J3.5 SAM, 0x0C = J12.0 Tasking
  sequenceNumber: bigint;
  spi: number; // Security Parameter Index / Net ID
  payloadLength: number;
}

export interface DissectedTacticalPacket {
  header: TacticalPacketHeader;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
  plaintext?: Uint8Array;
  authValid: boolean;
  replayStatus: 'ACCEPTED' | 'REPLAY_REJECTED' | 'EXPIRED_WINDOW';
}

export class TacticalPacketFramer {
  public static readonly MAGIC = 0x5153; // "QS"
  public static readonly VERSION = 0x02;

  private replayWindow = new AntiReplayWindow();
  private currentSeq = 1n;

  public resetReplayWindow(): void {
    this.replayWindow.reset();
    this.currentSeq = 1n;
  }

  /**
   * Constructs, encrypts, and authenticates a tactical COMSEC frame.
   */
  public framePacket(
    payload: Uint8Array,
    msgType: number,
    key: Uint8Array,
    spi: number = 0x00010001,
    explicitSeq?: bigint
  ): Uint8Array {
    const seq = explicitSeq ?? this.currentSeq++;

    // 18-Byte Header (Associated Data)
    const header = new Uint8Array(18);
    const hView = new DataView(header.buffer, header.byteOffset, 18);
    hView.setUint16(0, TacticalPacketFramer.MAGIC, false);
    hView.setUint8(2, TacticalPacketFramer.VERSION);
    hView.setUint8(3, msgType);
    hView.setBigUint64(4, seq, false);
    hView.setUint32(12, spi, false);
    hView.setUint16(16, payload.length, false);

    // 12-Byte Nonce: SPI (4B) || Seq (8B)
    const nonce = new Uint8Array(12);
    const nView = new DataView(nonce.buffer, nonce.byteOffset, 12);
    nView.setUint32(0, spi, false);
    nView.setBigUint64(4, seq, false);

    const { ciphertext, tag } = ChaCha20Poly1305AEAD.seal(key, nonce, payload, header);

    // Pack complete binary frame: Header (18) || Nonce (12) || Ciphertext (L) || Tag (16)
    const frame = new Uint8Array(18 + 12 + ciphertext.length + 16);
    frame.set(header, 0);
    frame.set(nonce, 18);
    frame.set(ciphertext, 30);
    frame.set(tag, 30 + ciphertext.length);

    return frame;
  }

  /**
   * Dissects, verifies anti-replay window, and decrypts a tactical COMSEC frame.
   */
  public dissectAndVerify(frame: Uint8Array, key: Uint8Array): DissectedTacticalPacket {
    if (frame.length < 18 + 12 + 16) {
      throw new Error('Frame is truncated (minimum size 46 bytes)');
    }

    const hView = new DataView(frame.buffer, frame.byteOffset, 18);
    const magic = hView.getUint16(0, false);
    const version = hView.getUint8(2);
    const msgType = hView.getUint8(3);
    const seq = hView.getBigUint64(4, false);
    const spi = hView.getUint32(12, false);
    const payloadLen = hView.getUint16(16, false);

    if (magic !== TacticalPacketFramer.MAGIC) {
      throw new Error(`Invalid magic: expected 0x${TacticalPacketFramer.MAGIC.toString(16)}`);
    }

    const header = frame.subarray(0, 18);
    const nonce = frame.subarray(18, 30);
    const ctEnd = 30 + payloadLen;
    const ciphertext = frame.subarray(30, ctEnd);
    const tag = frame.subarray(ctEnd, ctEnd + 16);

    const replayCheck = this.replayWindow.checkAndAdvance(seq);
    let replayStatus: DissectedTacticalPacket['replayStatus'] = 'ACCEPTED';
    if (!replayCheck.valid) {
      replayStatus = replayCheck.reason?.includes('expired') ? 'EXPIRED_WINDOW' : 'REPLAY_REJECTED';
    }

    const plaintext = ChaCha20Poly1305AEAD.open(key, nonce, ciphertext, header, tag);
    const authValid = plaintext !== null;

    return {
      header: {
        magic,
        version,
        msgType,
        sequenceNumber: seq,
        spi,
        payloadLength: payloadLen,
      },
      nonce,
      ciphertext,
      tag,
      plaintext: plaintext ?? undefined,
      authValid,
      replayStatus,
    };
  }
}
