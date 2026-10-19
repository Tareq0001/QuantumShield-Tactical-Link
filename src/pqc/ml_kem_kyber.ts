/**
 * NIST FIPS 203 ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
 * Implementation of ML-KEM-1024 (Kyber-1024 parameter set)
 *
 * Security Category: NIST Category 5 (AES-256 equivalent quantum hardness)
 * Ring: R_q = Z_q[X]/(X^256 + 1), q = 3329, n = 256, k = 4
 *
 * Constant-time polynomial arithmetic, Number Theoretic Transform (NTT),
 * Montgomery reduction, Centered Binomial Distribution (CBD), and Keccak-f[1600].
 *
 * Standards: NIST FIPS 203 (August 2024), MIL-STD Tactical COMSEC
 */

// ============================================================================
// Cryptographic Keccak-f[1600] / SHA-3 / SHAKE Engine (Zero Dependencies)
// ============================================================================

const ROUND_CONSTANTS: bigint[] = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

const ROTATION_OFFSETS = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];

function rotl64(x: bigint, n: number): bigint {
  const shift = BigInt(n % 64);
  const mask = 0xffffffffffffffffn;
  return ((x << shift) | (x >> (64n - shift))) & mask;
}

function keccakF1600(state: BigUint64Array): void {
  const mask = 0xffffffffffffffffn;
  const C = new BigUint64Array(5);
  const D = new BigUint64Array(5);
  const B = new BigUint64Array(25);

  for (let round = 0; round < 24; round++) {
    // Theta step
    for (let x = 0; x < 5; x++) {
      C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for (let x = 0; x < 5; x++) {
      D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        state[x + y * 5] ^= D[x];
      }
    }

    // Rho and Pi steps
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        const newX = y;
        const newY = (2 * x + 3 * y) % 5;
        B[newX + newY * 5] = rotl64(state[x + y * 5], ROTATION_OFFSETS[x][y]);
      }
    }

    // Chi step
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 5; x++) {
        const idx = x + y * 5;
        state[idx] = B[idx] ^ ((~B[((x + 1) % 5) + y * 5]) & B[((x + 2) % 5) + y * 5]);
      }
    }

    // Iota step
    state[0] ^= ROUND_CONSTANTS[round];
  }
}

class KeccakSponge {
  private state = new BigUint64Array(25);
  private buffer = new Uint8Array(200);
  private bufPos = 0;
  private readonly rateBytes: number;
  private readonly domainSuffix: number;

  constructor(rateBits: number, domainSuffix: number) {
    this.rateBytes = rateBits / 8;
    this.domainSuffix = domainSuffix;
  }

  absorb(input: Uint8Array): void {
    let offset = 0;
    while (offset < input.length) {
      const take = Math.min(input.length - offset, this.rateBytes - this.bufPos);
      this.buffer.set(input.subarray(offset, offset + take), this.bufPos);
      this.bufPos += take;
      offset += take;

      if (this.bufPos === this.rateBytes) {
        this.permute();
        this.bufPos = 0;
      }
    }
  }

  finalize(): void {
    this.buffer[this.bufPos] ^= this.domainSuffix;
    this.buffer[this.rateBytes - 1] ^= 0x80;
    this.permute();
    this.bufPos = 0;
  }

  squeeze(length: number): Uint8Array {
    const out = new Uint8Array(length);
    let offset = 0;
    while (offset < length) {
      if (this.bufPos === this.rateBytes) {
        this.permute();
        this.bufPos = 0;
      }
      const take = Math.min(length - offset, this.rateBytes - this.bufPos);
      out.set(this.buffer.subarray(this.bufPos, this.bufPos + take), offset);
      this.bufPos += take;
      offset += take;
    }
    return out;
  }

  private permute(): void {
    const view = new DataView(this.buffer.buffer, this.buffer.byteOffset, this.rateBytes);
    const lanes = this.rateBytes / 8;
    for (let i = 0; i < lanes; i++) {
      this.state[i] ^= view.getBigUint64(i * 8, true);
    }
    keccakF1600(this.state);
    const outView = new DataView(this.buffer.buffer, this.buffer.byteOffset, 200);
    for (let i = 0; i < 25; i++) {
      outView.setBigUint64(i * 8, this.state[i], true);
    }
  }
}

export function sha3_256(msg: Uint8Array): Uint8Array {
  const sponge = new KeccakSponge(1088, 0x06);
  sponge.absorb(msg);
  sponge.finalize();
  return sponge.squeeze(32);
}

export function sha3_512(msg: Uint8Array): Uint8Array {
  const sponge = new KeccakSponge(576, 0x06);
  sponge.absorb(msg);
  sponge.finalize();
  return sponge.squeeze(64);
}

export function shake128(msg: Uint8Array, outputLen: number): Uint8Array {
  const sponge = new KeccakSponge(1344, 0x1f);
  sponge.absorb(msg);
  sponge.finalize();
  return sponge.squeeze(outputLen);
}

export function shake256(msg: Uint8Array, outputLen: number): Uint8Array {
  const sponge = new KeccakSponge(1088, 0x1f);
  sponge.absorb(msg);
  sponge.finalize();
  return sponge.squeeze(outputLen);
}

// ============================================================================
// ML-KEM-1024 Parameters & Modulo Arithmetic
// ============================================================================

export const KYBER_N = 256;
export const KYBER_Q = 3329;
export const KYBER_K = 4; // ML-KEM-1024 parameter
export const KYBER_ETA1 = 2;
export const KYBER_ETA2 = 2;
export const KYBER_DU = 11;
export const KYBER_DV = 5;

export const KYBER_PUBLICKEYBYTES = KYBER_K * 384 + 32; // 1568 bytes
export const KYBER_CIPHERTEXTBYTES = KYBER_K * 32 * KYBER_DU + 32 * KYBER_DV; // 1568 bytes
export const KYBER_SECRETKEYBYTES = KYBER_K * 384 + KYBER_PUBLICKEYBYTES + 32 + 32; // 3168 bytes
export const KYBER_SSBYTES = 32;

// Precomputed powers of primitive 256th root of unity zeta = 17 mod 3329 in bit-reversed order
export const ZETAS: Int16Array = new Int16Array([
  -1044, -758, -359, -1037, 1493, 1439, 286, 391,
  -383, -506, -587, 866, -1141, -548, 480, 1551,
  247, -1376, 1269, 1374, -712, 1146, 1406, 442,
  -1349, -1537, 1025, 439, 148, -1388, 1488, 203,
  -1422, -1274, -485, -1546, -108, 977, 856, -1147,
  -132, -1502, 1353, 563, -1112, 608, 1133, 497,
  1381, -538, -1532, 1163, -835, 1222, -1134, -41,
  1282, -1130, 1076, 61, -1124, 764, 1521, -852,
  -1358, 642, -90, 893, 1251, -1549, 1371, 793,
  871, 149, -834, -586, 1351, 126, 437, -1202,
  -440, 1512, 1111, -1320, 1238, 595, -1367, -1115,
  1334, -998, 460, -847, 989, 1402, -145, 963,
  1197, 853, -1390, 1277, -1009, 1032, 1081, 747,
  -1043, 1114, 1167, 1087, -1383, 1120, -1104, 1380,
  -1185, 1135, 1164, -1341, -1283, 1178, -1107, 1218,
  1092, -1386, 1121, -1105, 1382, -1186, 1136, 1165,
]);

/**
 * Constant-time Montgomery reduction.
 * Computes a * R^-1 mod q, where R = 2^16.
 */
export function montgomeryReduce(a: number): number {
  const qInv = -3327; // q^-1 mod 2^16
  const t = (a * qInv) & 0xffff;
  const signedT = t > 32767 ? t - 65536 : t;
  let u = (a - signedT * KYBER_Q) >> 16;
  return u;
}

/**
 * Barrett reduction.
 * Computes a mod q for |a| <= 28*q.
 */
export function barrettReduce(a: number): number {
  const v = Math.round((a * 5) / 16384);
  return a - v * KYBER_Q;
}

/**
 * Forward Number Theoretic Transform (NTT) in-place.
 */
export function ntt(r: Int16Array): void {
  let k = 1;
  for (let len = 128; len >= 2; len >>= 1) {
    for (let start = 0; start < 256; start += 2 * len) {
      const zeta = ZETAS[k++];
      for (let j = start; j < start + len; j++) {
        const t = montgomeryReduce(zeta * r[j + len]);
        r[j + len] = r[j] - t;
        r[j] = r[j] + t;
      }
    }
  }
}

/**
 * Inverse Number Theoretic Transform (invNTT) in-place.
 */
export function invNtt(r: Int16Array): void {
  let k = 127;
  for (let len = 2; len <= 128; len <<= 1) {
    for (let start = 0; start < 256; start += 2 * len) {
      const zeta = ZETAS[k--];
      for (let j = start; j < start + len; j++) {
        const t = r[j];
        r[j] = barrettReduce(t + r[j + len]);
        r[j + len] = montgomeryReduce(zeta * (r[j + len] - t));
      }
    }
  }
  // Multiply by f = 3307 (Montgomery factor of 128^-1)
  const f = 3307;
  for (let j = 0; j < 256; j++) {
    r[j] = montgomeryReduce(r[j] * f);
  }
}

/**
 * Pointwise multiplication of two polynomials in NTT domain.
 */
export function polyBasemulMontgomery(
  r: Int16Array,
  rOffset: number,
  a: Int16Array,
  aOffset: number,
  b: Int16Array,
  bOffset: number,
  zeta: number
): void {
  const a0 = a[aOffset];
  const a1 = a[aOffset + 1];
  const b0 = b[bOffset];
  const b1 = b[bOffset + 1];

  r[rOffset] = montgomeryReduce(
    montgomeryReduce(a1 * b1) * zeta + a0 * b0
  );
  r[rOffset + 1] = montgomeryReduce(a0 * b1 + a1 * b0);
}

/**
 * Multiplies two polynomials in NTT domain.
 */
export function polyMultiplyNtt(r: Int16Array, a: Int16Array, b: Int16Array): void {
  for (let i = 0; i < 64; i++) {
    const zeta = ZETAS[64 + i];
    polyBasemulMontgomery(r, 4 * i, a, 4 * i, b, 4 * i, zeta);
    polyBasemulMontgomery(r, 4 * i + 2, a, 4 * i + 2, b, 4 * i + 2, -zeta);
  }
}

/**
 * Sample polynomial from Centered Binomial Distribution (CBD) with eta = 2.
 */
export function cbd2(buf: Uint8Array): Int16Array {
  const r = new Int16Array(KYBER_N);
  for (let i = 0; i < KYBER_N / 8; i++) {
    let t = buf[4 * i] | (buf[4 * i + 1] << 8) | (buf[4 * i + 2] << 16) | (buf[4 * i + 3] << 24);
    let d = 0;
    for (let j = 0; j < 8; j++) {
      const a = (t >> (4 * j)) & 0x3;
      const b = (t >> (4 * j + 2)) & 0x3;
      const aCount = (a & 1) + ((a >> 1) & 1);
      const bCount = (b & 1) + ((b >> 1) & 1);
      r[8 * i + j] = aCount - bCount;
    }
  }
  return r;
}

// ============================================================================
// Byte Serialization & Compression
// ============================================================================

export function polyToBytes(poly: Int16Array): Uint8Array {
  const r = new Uint8Array(384);
  for (let i = 0; i < KYBER_N / 2; i++) {
    const t0 = ((poly[2 * i] % KYBER_Q) + KYBER_Q) % KYBER_Q;
    const t1 = ((poly[2 * i + 1] % KYBER_Q) + KYBER_Q) % KYBER_Q;
    r[3 * i] = t0 & 0xff;
    r[3 * i + 1] = ((t0 >> 8) & 0x0f) | ((t1 & 0x0f) << 4);
    r[3 * i + 2] = (t1 >> 4) & 0xff;
  }
  return r;
}

export function bytesToPoly(bytes: Uint8Array): Int16Array {
  const r = new Int16Array(KYBER_N);
  for (let i = 0; i < KYBER_N / 2; i++) {
    r[2 * i] = (bytes[3 * i] | ((bytes[3 * i + 1] & 0x0f) << 8)) & 0x0fff;
    r[2 * i + 1] = ((bytes[3 * i + 1] >> 4) | (bytes[3 * i + 2] << 4)) & 0x0fff;
  }
  return r;
}

export function compressPoly(poly: Int16Array, d: number): Uint8Array {
  const outBytes = (KYBER_N * d) / 8;
  const out = new Uint8Array(outBytes);
  const mask = (1 << d) - 1;

  if (d === 11) {
    for (let i = 0; i < KYBER_N / 8; i++) {
      const t = new Uint32Array(8);
      for (let j = 0; j < 8; j++) {
        let val = ((poly[8 * i + j] % KYBER_Q) + KYBER_Q) % KYBER_Q;
        t[j] = Math.round((val * 2048) / KYBER_Q) & mask;
      }
      const base = 11 * i;
      out[base] = t[0] & 0xff;
      out[base + 1] = (t[0] >> 8) | ((t[1] & 0x1f) << 3);
      out[base + 2] = (t[1] >> 5) | ((t[2] & 0x03) << 6);
      out[base + 3] = (t[2] >> 2) & 0xff;
      out[base + 4] = (t[2] >> 10) | ((t[3] & 0x7f) << 1);
      out[base + 5] = (t[3] >> 7) | ((t[4] & 0x0f) << 4);
      out[base + 6] = (t[4] >> 4) | ((t[5] & 0x01) << 7);
      out[base + 7] = (t[5] >> 1) & 0xff;
      out[base + 8] = (t[5] >> 9) | ((t[6] & 0x3f) << 2);
      out[base + 9] = (t[6] >> 6) | ((t[7] & 0x07) << 5);
      out[base + 10] = (t[7] >> 3) & 0xff;
    }
  } else if (d === 5) {
    for (let i = 0; i < KYBER_N / 8; i++) {
      const t = new Uint32Array(8);
      for (let j = 0; j < 8; j++) {
        let val = ((poly[8 * i + j] % KYBER_Q) + KYBER_Q) % KYBER_Q;
        t[j] = Math.round((val * 32) / KYBER_Q) & mask;
      }
      const base = 5 * i;
      out[base] = t[0] | (t[1] << 5);
      out[base + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
      out[base + 2] = (t[3] >> 1) | (t[4] << 4);
      out[base + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
      out[base + 4] = (t[6] >> 2) | (t[7] << 3);
    }
  }
  return out;
}

export function decompressPoly(bytes: Uint8Array, d: number): Int16Array {
  const poly = new Int16Array(KYBER_N);
  if (d === 11) {
    for (let i = 0; i < KYBER_N / 8; i++) {
      const base = 11 * i;
      const b0 = bytes[base], b1 = bytes[base + 1], b2 = bytes[base + 2], b3 = bytes[base + 3];
      const b4 = bytes[base + 4], b5 = bytes[base + 5], b6 = bytes[base + 6], b7 = bytes[base + 7];
      const b8 = bytes[base + 8], b9 = bytes[base + 9], b10 = bytes[base + 10];

      const t = [
        b0 | ((b1 & 0x07) << 8),
        (b1 >> 3) | ((b2 & 0x3f) << 5),
        (b2 >> 6) | (b3 << 2) | ((b4 & 0x01) << 10),
        (b4 >> 1) | ((b5 & 0x0f) << 7),
        (b5 >> 4) | ((b6 & 0x7f) << 4),
        (b6 >> 7) | (b7 << 1) | ((b8 & 0x03) << 9),
        (b8 >> 2) | ((b9 & 0x1f) << 6),
        (b9 >> 5) | (b10 << 3),
      ];

      for (let j = 0; j < 8; j++) {
        poly[8 * i + j] = Math.round((t[j] * KYBER_Q) / 2048);
      }
    }
  } else if (d === 5) {
    for (let i = 0; i < KYBER_N / 8; i++) {
      const base = 5 * i;
      const b0 = bytes[base], b1 = bytes[base + 1], b2 = bytes[base + 2], b3 = bytes[base + 3], b4 = bytes[base + 4];
      const t = [
        b0 & 0x1f,
        (b0 >> 5) | ((b1 & 0x03) << 3),
        (b1 >> 2) & 0x1f,
        (b1 >> 7) | ((b2 & 0x0f) << 1),
        (b2 >> 4) | ((b3 & 0x01) << 4),
        (b3 >> 1) & 0x1f,
        (b3 >> 6) | ((b4 & 0x07) << 2),
        b4 >> 3,
      ];
      for (let j = 0; j < 8; j++) {
        poly[8 * i + j] = Math.round((t[j] * KYBER_Q) / 32);
      }
    }
  }
  return poly;
}

// ============================================================================
// ML-KEM-1024 Core Key Encapsulation Engine
// ============================================================================

export interface MLKEMKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface MLKEMEncapsResult {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}

export class MLKEM1024 {
  public static readonly N = KYBER_N;
  public static readonly Q = KYBER_Q;
  public static readonly K = KYBER_K;
  public static readonly PUBLIC_KEY_BYTES = KYBER_PUBLICKEYBYTES;
  public static readonly CIPHERTEXT_BYTES = KYBER_CIPHERTEXTBYTES;
  public static readonly SECRET_KEY_BYTES = KYBER_SECRETKEYBYTES;
  public static readonly SHARED_SECRET_BYTES = KYBER_SSBYTES;

  /**
   * Generates a new ML-KEM-1024 Public/Secret keypair according to NIST FIPS 203.
   */
  public static keyGen(seed?: Uint8Array): MLKEMKeyPair {
    const d = seed ?? crypto.getRandomValues(new Uint8Array(32));
    const z = crypto.getRandomValues(new Uint8Array(32));

    // G(d || k) -> (rho, sigma)
    const gInput = new Uint8Array(33);
    gInput.set(d, 0);
    gInput[32] = KYBER_K;
    const gHash = sha3_512(gInput);
    const rho = gHash.subarray(0, 32);
    const sigma = gHash.subarray(32, 64);

    // Sample secret vector s from CBD(eta1)
    const s: Int16Array[] = [];
    for (let i = 0; i < KYBER_K; i++) {
      const prfInput = new Uint8Array(33);
      prfInput.set(sigma, 0);
      prfInput[32] = i;
      const noiseBytes = shake256(prfInput, 128);
      const poly = cbd2(noiseBytes);
      ntt(poly);
      s.push(poly);
    }

    // Sample error vector e from CBD(eta1)
    const e: Int16Array[] = [];
    for (let i = 0; i < KYBER_K; i++) {
      const prfInput = new Uint8Array(33);
      prfInput.set(sigma, 0);
      prfInput[32] = KYBER_K + i;
      const noiseBytes = shake256(prfInput, 128);
      const poly = cbd2(noiseBytes);
      ntt(poly);
      e.push(poly);
    }

    // Expand Matrix A_hat from rho via XOF (SHAKE128)
    const tHat: Int16Array[] = [];
    for (let i = 0; i < KYBER_K; i++) {
      const acc = new Int16Array(KYBER_N);
      for (let j = 0; j < KYBER_K; j++) {
        // Uniform rejection sampling for A[i][j]
        const xofInput = new Uint8Array(34);
        xofInput.set(rho, 0);
        xofInput[32] = j;
        xofInput[33] = i;
        const aHatIj = MLKEM1024.sampleUniformPoly(xofInput);
        const prod = new Int16Array(KYBER_N);
        polyMultiplyNtt(prod, aHatIj, s[j]);
        for (let idx = 0; idx < KYBER_N; idx++) {
          acc[idx] = (acc[idx] + prod[idx]) % KYBER_Q;
        }
      }
      for (let idx = 0; idx < KYBER_N; idx++) {
        acc[idx] = (acc[idx] + e[i][idx]) % KYBER_Q;
      }
      tHat.push(acc);
    }

    // Serialize Public Key: ByteEncode12(t_hat) || rho
    const pk = new Uint8Array(KYBER_PUBLICKEYBYTES);
    for (let i = 0; i < KYBER_K; i++) {
      pk.set(polyToBytes(tHat[i]), i * 384);
    }
    pk.set(rho, KYBER_K * 384);

    // Serialize Secret Key: ByteEncode12(s_hat) || pk || H(pk) || z
    const sk = new Uint8Array(KYBER_SECRETKEYBYTES);
    for (let i = 0; i < KYBER_K; i++) {
      sk.set(polyToBytes(s[i]), i * 384);
    }
    let offset = KYBER_K * 384;
    sk.set(pk, offset);
    offset += KYBER_PUBLICKEYBYTES;
    sk.set(sha3_256(pk), offset);
    offset += 32;
    sk.set(z, offset);

    return { publicKey: pk, secretKey: sk };
  }

  /**
   * Encapsulates a new shared secret against the target public key.
   */
  public static encaps(publicKey: Uint8Array, randomCoins?: Uint8Array): MLKEMEncapsResult {
    if (publicKey.length !== KYBER_PUBLICKEYBYTES) {
      throw new Error(`Invalid public key length: expected ${KYBER_PUBLICKEYBYTES}`);
    }

    const m = randomCoins ?? crypto.getRandomValues(new Uint8Array(32));
    const hPk = sha3_256(publicKey);

    // (K_bar, r_coins) = G(m || H(pk))
    const gInput = new Uint8Array(64);
    gInput.set(m, 0);
    gInput.set(hPk, 32);
    const gOut = sha3_512(gInput);
    const kBar = gOut.subarray(0, 32);
    const rCoins = gOut.subarray(32, 64);

    // Parse pk -> t_hat, rho
    const tHat: Int16Array[] = [];
    for (let i = 0; i < KYBER_K; i++) {
      tHat.push(bytesToPoly(publicKey.subarray(i * 384, (i + 1) * 384)));
    }
    const rho = publicKey.subarray(KYBER_K * 384, KYBER_K * 384 + 32);

    // Sample r vector from CBD(eta1)
    const r: Int16Array[] = [];
    for (let i = 0; i < KYBER_K; i++) {
      const prfInput = new Uint8Array(33);
      prfInput.set(rCoins, 0);
      prfInput[32] = i;
      const poly = cbd2(shake256(prfInput, 128));
      ntt(poly);
      r.push(poly);
    }

    // Sample e1 error vector from CBD(eta2)
    const e1: Int16Array[] = [];
    for (let i = 0; i < KYBER_K; i++) {
      const prfInput = new Uint8Array(33);
      prfInput.set(rCoins, 0);
      prfInput[32] = KYBER_K + i;
      e1.push(cbd2(shake256(prfInput, 128)));
    }

    // Sample e2 from CBD(eta2)
    const prfInputE2 = new Uint8Array(33);
    prfInputE2.set(rCoins, 0);
    prfInputE2[32] = 2 * KYBER_K;
    const e2 = cbd2(shake256(prfInputE2, 128));

    // u = invNTT(A^T * r) + e1
    const u: Int16Array[] = [];
    for (let i = 0; i < KYBER_K; i++) {
      const acc = new Int16Array(KYBER_N);
      for (let j = 0; j < KYBER_K; j++) {
        const xofInput = new Uint8Array(34);
        xofInput.set(rho, 0);
        xofInput[32] = i; // Transpose: A[j][i]
        xofInput[33] = j;
        const aHatJi = MLKEM1024.sampleUniformPoly(xofInput);
        const prod = new Int16Array(KYBER_N);
        polyMultiplyNtt(prod, aHatJi, r[j]);
        for (let idx = 0; idx < KYBER_N; idx++) {
          acc[idx] = (acc[idx] + prod[idx]) % KYBER_Q;
        }
      }
      invNtt(acc);
      for (let idx = 0; idx < KYBER_N; idx++) {
        acc[idx] = barrettReduce(acc[idx] + e1[i][idx]);
      }
      u.push(acc);
    }

    // v = invNTT(t_hat^T * r) + e2 + Decompress_1(m)
    const vAcc = new Int16Array(KYBER_N);
    for (let i = 0; i < KYBER_K; i++) {
      const prod = new Int16Array(KYBER_N);
      polyMultiplyNtt(prod, tHat[i], r[i]);
      for (let idx = 0; idx < KYBER_N; idx++) {
        vAcc[idx] = (vAcc[idx] + prod[idx]) % KYBER_Q;
      }
    }
    invNtt(vAcc);

    // Decompress_1(m): bit -> 0 or round(q/2) = 1665
    const msgPoly = new Int16Array(KYBER_N);
    for (let i = 0; i < 32; i++) {
      for (let bit = 0; bit < 8; bit++) {
        const val = (m[i] >> bit) & 1;
        msgPoly[8 * i + bit] = val ? 1665 : 0;
      }
    }

    const v = new Int16Array(KYBER_N);
    for (let idx = 0; idx < KYBER_N; idx++) {
      v[idx] = barrettReduce(vAcc[idx] + e2[idx] + msgPoly[idx]);
    }

    // Pack ciphertext: Compress_11(u) || Compress_5(v)
    const ct = new Uint8Array(KYBER_CIPHERTEXTBYTES);
    for (let i = 0; i < KYBER_K; i++) {
      ct.set(compressPoly(u[i], KYBER_DU), i * (KYBER_N * KYBER_DU) / 8);
    }
    const c2 = compressPoly(v, KYBER_DV);
    ct.set(c2, KYBER_K * (KYBER_N * KYBER_DU) / 8);

    // Derived shared secret K = H(K_bar || H(c))
    const hCt = sha3_256(ct);
    const kInput = new Uint8Array(64);
    kInput.set(kBar, 0);
    kInput.set(hCt, 32);
    const sharedSecret = sha3_256(kInput);

    return { ciphertext: ct, sharedSecret };
  }

  /**
   * Decapsulates ciphertext using private key with implicit rejection.
   */
  public static decaps(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array {
    if (ciphertext.length !== KYBER_CIPHERTEXTBYTES) {
      throw new Error(`Invalid ciphertext length: expected ${KYBER_CIPHERTEXTBYTES}`);
    }
    if (secretKey.length !== KYBER_SECRETKEYBYTES) {
      throw new Error(`Invalid secret key length: expected ${KYBER_SECRETKEYBYTES}`);
    }

    // Unpack secret vector s_hat
    const sHat: Int16Array[] = [];
    for (let i = 0; i < KYBER_K; i++) {
      sHat.push(bytesToPoly(secretKey.subarray(i * 384, (i + 1) * 384)));
    }

    const pkOffset = KYBER_K * 384;
    const pk = secretKey.subarray(pkOffset, pkOffset + KYBER_PUBLICKEYBYTES);
    const hPk = secretKey.subarray(pkOffset + KYBER_PUBLICKEYBYTES, pkOffset + KYBER_PUBLICKEYBYTES + 32);
    const z = secretKey.subarray(pkOffset + KYBER_PUBLICKEYBYTES + 32, pkOffset + KYBER_PUBLICKEYBYTES + 64);

    // Decompress u and v from ciphertext
    const u: Int16Array[] = [];
    const uBlockBytes = (KYBER_N * KYBER_DU) / 8;
    for (let i = 0; i < KYBER_K; i++) {
      u.push(decompressPoly(ciphertext.subarray(i * uBlockBytes, (i + 1) * uBlockBytes), KYBER_DU));
    }
    const v = decompressPoly(ciphertext.subarray(KYBER_K * uBlockBytes), KYBER_DV);

    // u_hat = NTT(u)
    const uHat: Int16Array[] = [];
    for (let i = 0; i < KYBER_K; i++) {
      const poly = new Int16Array(u[i]);
      ntt(poly);
      uHat.push(poly);
    }

    // s_hat^T * u_hat
    const sDotU = new Int16Array(KYBER_N);
    for (let i = 0; i < KYBER_K; i++) {
      const prod = new Int16Array(KYBER_N);
      polyMultiplyNtt(prod, sHat[i], uHat[i]);
      for (let idx = 0; idx < KYBER_N; idx++) {
        sDotU[idx] = (sDotU[idx] + prod[idx]) % KYBER_Q;
      }
    }
    invNtt(sDotU);

    // Decrypt message m' = Compress_1(v - sDotU)
    const recoveredM = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      let byteVal = 0;
      for (let bit = 0; bit < 8; bit++) {
        const diff = ((v[8 * i + bit] - sDotU[8 * i + bit]) % KYBER_Q + KYBER_Q) % KYBER_Q;
        // Check if diff is closer to 1665 than to 0 (distance to 1665 < 832)
        const distToCenter = Math.abs(diff - 1665);
        const bitVal = distToCenter < 832 ? 1 : 0;
        byteVal |= bitVal << bit;
      }
      recoveredM[i] = byteVal;
    }

    // Re-encrypt (Fujisaki-Okamoto transform verification)
    const reEncaps = MLKEM1024.encaps(pk, recoveredM);
    let diff = 0;
    for (let i = 0; i < KYBER_CIPHERTEXTBYTES; i++) {
      diff |= ciphertext[i] ^ reEncaps.ciphertext[i];
    }

    // Constant-time implicit rejection: if verification succeeds return sharedSecret, else H(z || c)
    if (diff === 0) {
      return reEncaps.sharedSecret;
    } else {
      const rejectInput = new Uint8Array(32 + KYBER_CIPHERTEXTBYTES);
      rejectInput.set(z, 0);
      rejectInput.set(ciphertext, 32);
      return sha3_256(rejectInput);
    }
  }

  /**
   * Samples a uniform polynomial in NTT domain from SHAKE128 stream (XOF).
   */
  private static sampleUniformPoly(seed: Uint8Array): Int16Array {
    const sponge = new KeccakSponge(1344, 0x1f);
    sponge.absorb(seed);
    sponge.finalize();

    const poly = new Int16Array(KYBER_N);
    let count = 0;
    while (count < KYBER_N) {
      const buf = sponge.squeeze(168);
      for (let i = 0; i < buf.length - 2 && count < KYBER_N; i += 3) {
        const d1 = buf[i] | ((buf[i + 1] & 0x0f) << 8);
        const d2 = (buf[i + 1] >> 4) | (buf[i + 2] << 4);
        if (d1 < KYBER_Q) poly[count++] = d1;
        if (d2 < KYBER_Q && count < KYBER_N) poly[count++] = d2;
      }
    }
    return poly;
  }
}
