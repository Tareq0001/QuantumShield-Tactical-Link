/**
 * QuantumShield Comprehensive Cryptographic & COMSEC Test Suite
 * Vitest Unit Tests for:
 * - NIST FIPS 203 ML-KEM-1024 (Kyber-1024) Polynomial Lattice Cryptography & NTT
 * - BB84 Quantum Key Distribution & Optical Eavesdrop Detection
 * - Tactical Frequency Hopping (FHSS) TRANSEC Hop Synthesis
 * - ChaCha20-Poly1305 AEAD & 64-Bit Anti-Replay Sliding Window
 */

import { describe, it, expect } from 'vitest';
import {
  MLKEM1024,
  ntt,
  invNtt,
  KYBER_PUBLICKEYBYTES,
  KYBER_SECRETKEYBYTES,
  KYBER_CIPHERTEXTBYTES,
  KYBER_SSBYTES,
  KYBER_Q,
  KYBER_N,
  sha3_256,
} from '../src/pqc/ml_kem_kyber.ts';
import { BB84Protocol } from '../src/qkd/bb84_protocol.ts';
import { FHSSTransec, TACTICAL_BANDS } from '../src/comsec/fhss_transec.ts';
import {
  TacticalPacketFramer,
  AntiReplayWindow,
  ChaCha20Poly1305AEAD,
} from '../src/crypto/aead_chacha20_gcm.ts';

// ============================================================================
// 1. NIST FIPS 203 ML-KEM-1024 Verification
// ============================================================================

describe('NIST FIPS 203 ML-KEM-1024 (Kyber-1024)', () => {
  it('should verify NTT and invNTT reversibility over ring R_q', () => {
    const original = new Int16Array(KYBER_N);
    const testPoly = new Int16Array(KYBER_N);

    for (let i = 0; i < KYBER_N; i++) {
      original[i] = ((i * 17 + 5) % KYBER_Q);
      testPoly[i] = original[i];
    }

    ntt(testPoly);
    invNtt(testPoly);

    for (let i = 0; i < KYBER_N; i++) {
      const diff = ((testPoly[i] - original[i]) % KYBER_Q + KYBER_Q) % KYBER_Q;
      expect(diff).toBe(0);
    }
  });

  it('should generate valid keypair with standard FIPS 203 byte dimensions', () => {
    const seed = new Uint8Array(32).fill(0x42);
    const keyPair = MLKEM1024.keyGen(seed);

    expect(keyPair.publicKey.length).toBe(KYBER_PUBLICKEYBYTES); // 1568
    expect(keyPair.secretKey.length).toBe(KYBER_SECRETKEYBYTES); // 3168
  });

  it('should encapsulate and decapsulate identical shared secret (K_Alice === K_Bob)', () => {
    const keyPair = MLKEM1024.keyGen();
    const encapsResult = MLKEM1024.encaps(keyPair.publicKey);

    expect(encapsResult.ciphertext.length).toBe(KYBER_CIPHERTEXTBYTES); // 1568
    expect(encapsResult.sharedSecret.length).toBe(KYBER_SSBYTES); // 32

    const decapsSecret = MLKEM1024.decaps(encapsResult.ciphertext, keyPair.secretKey);
    expect(decapsSecret.length).toBe(KYBER_SSBYTES);

    // Verify cryptographic equality
    expect(Array.from(decapsSecret)).toEqual(Array.from(encapsResult.sharedSecret));
  });

  it('should implicitly reject corrupted ciphertext and produce pseudorandom secret', () => {
    const keyPair = MLKEM1024.keyGen();
    const { ciphertext, sharedSecret } = MLKEM1024.encaps(keyPair.publicKey);

    // Tamper with one byte of ciphertext
    const corruptedCt = new Uint8Array(ciphertext);
    corruptedCt[42] ^= 0x5a;

    const rejectedSecret = MLKEM1024.decaps(corruptedCt, keyPair.secretKey);

    // Must be 32 bytes but NOT equal to the genuine shared secret
    expect(rejectedSecret.length).toBe(32);
    expect(Array.from(rejectedSecret)).not.toEqual(Array.from(sharedSecret));
  });
});

// ============================================================================
// 2. BB84 Quantum Key Distribution Protocol
// ============================================================================

describe('BB84 Quantum Key Distribution Protocol', () => {
  it('should establish secure quantum key over honest optical channel with low QBER', () => {
    const res = BB84Protocol.simulate({
      numPhotons: 1024,
      fiberLengthKm: 10.0,
      attenuationDbPerKm: 0.20,
      eavesdropperPresent: false,
    });

    expect(res.protocolStatus).toBe('SECURE_KEY_ESTABLISHED');
    expect(res.eavesdropperDetected).toBe(false);
    expect(res.qber).toBeLessThan(0.06); // < 6%
    expect(res.finalKeyBytes.length).toBeGreaterThanOrEqual(16);
    expect(res.finalKeyHex.length).toBeGreaterThanOrEqual(32);
  });

  it('should detect eavesdropper and securely abort when QBER exceeds threshold', () => {
    const res = BB84Protocol.simulate({
      numPhotons: 1024,
      fiberLengthKm: 10.0,
      eavesdropperPresent: true,
      eavesdropProbability: 1.0, // 100% Intercept-Resend
      qberThreshold: 0.11,
    });

    expect(res.eavesdropperDetected).toBe(true);
    expect(res.protocolStatus).toBe('ABORTED_EAVESDROPPER_DETECTED');
    expect(res.qber).toBeGreaterThan(0.18); // ~25%
    expect(res.finalKeyBytes.length).toBe(0);
  });
});

// ============================================================================
// 3. Fast Frequency Hopping (FHSS) TRANSEC Engine
// ============================================================================

describe('FHSS TRANSEC Hop Generation', () => {
  it('should deterministically produce identical hop sequences with matching cryptovariables', () => {
    const key = new Uint8Array(32).fill(0x77);
    const tod = 1729000000;
    const wod = '301.250';
    const netId = 7;

    const seq1 = FHSSTransec.generateHopSequence(key, tod, wod, netId, 20, 'LINK16');
    const seq2 = FHSSTransec.generateHopSequence(key, tod, wod, netId, 20, 'LINK16');

    expect(seq1.length).toBe(20);
    for (let i = 0; i < 20; i++) {
      expect(seq1[i].frequencyMhz).toBe(seq2[i].frequencyMhz);
      expect(seq1[i].channelIndex).toBe(seq2[i].channelIndex);
    }
  });

  it('should produce strictly valid frequencies adhering to Link-16 band and IFF notch exclusion', () => {
    const key = sha3_256(new TextEncoder().encode('SAUDI-TACTICAL-KEY'));
    const hops = FHSSTransec.generateHopSequence(key, 123456, '999.999', 1, 100, 'LINK16');

    const band = TACTICAL_BANDS.LINK16;
    for (const hop of hops) {
      expect(hop.frequencyMhz).toBeGreaterThanOrEqual(band.minFreqMhz);
      expect(hop.frequencyMhz).toBeLessThanOrEqual(band.maxFreqMhz);

      // Verify no hop falls into protected IFF notch bands (1030 MHz and 1090 MHz)
      expect(hop.frequencyMhz < 1025.0 || hop.frequencyMhz > 1035.0).toBe(true);
      expect(hop.frequencyMhz < 1085.0 || hop.frequencyMhz > 1095.0).toBe(true);
    }
  });

  it('should compute tactical anti-jamming margin with positive process gain', () => {
    const aj = FHSSTransec.computeAntiJamMargin('LINK16', 128);
    expect(aj.processGainDb).toBeGreaterThan(30.0);
    expect(aj.antiJamMarginDb).toBeGreaterThan(15.0);
  });
});

// ============================================================================
// 4. ChaCha20-Poly1305 AEAD & 64-bit Anti-Replay Sliding Window
// ============================================================================

describe('Tactical AEAD & Anti-Replay Framing', () => {
  it('should successfully encrypt and authenticate tactical payloads', () => {
    const key = new Uint8Array(32).fill(0x33);
    const nonce = new Uint8Array(12).fill(0x01);
    const plaintext = new TextEncoder().encode('LINK-16 J2.2 PPLI TARGET AIRBORNE');
    const aad = new Uint8Array([0x51, 0x53, 0x02, 0x02]);

    const { ciphertext, tag } = ChaCha20Poly1305AEAD.seal(key, nonce, plaintext, aad);
    expect(ciphertext.length).toBe(plaintext.length);
    expect(tag.length).toBe(16);

    const decrypted = ChaCha20Poly1305AEAD.open(key, nonce, ciphertext, aad, tag);
    expect(decrypted).not.toBeNull();
    expect(new TextDecoder().decode(decrypted!)).toBe('LINK-16 J2.2 PPLI TARGET AIRBORNE');
  });

  it('should reject tampered AEAD ciphertext or invalid tag', () => {
    const key = new Uint8Array(32).fill(0x55);
    const nonce = new Uint8Array(12).fill(0x02);
    const plaintext = new TextEncoder().encode('CLASSIFIED MISSION ORDER');
    const aad = new Uint8Array([0x01, 0x02]);

    const { ciphertext, tag } = ChaCha20Poly1305AEAD.seal(key, nonce, plaintext, aad);

    // Tamper ciphertext
    const badCt = new Uint8Array(ciphertext);
    badCt[0] ^= 0x01;
    const failRes = ChaCha20Poly1305AEAD.open(key, nonce, badCt, aad, tag);
    expect(failRes).toBeNull();
  });

  it('should enforce 64-bit anti-replay window and reject duplicate / replayed packets', () => {
    const window = new AntiReplayWindow();

    // In-order packet 1..5
    expect(window.checkAndAdvance(1n).valid).toBe(true);
    expect(window.checkAndAdvance(2n).valid).toBe(true);
    expect(window.checkAndAdvance(3n).valid).toBe(true);

    // Replay attack: sequence 2 sent again
    const replayRes = window.checkAndAdvance(2n);
    expect(replayRes.valid).toBe(false);
    expect(replayRes.reason).toContain('Replay attack detected');

    // Out-of-order jump within window (seq 15)
    expect(window.checkAndAdvance(15n).valid).toBe(true);

    // Intermediate out-of-order packet (seq 10) arrives
    expect(window.checkAndAdvance(10n).valid).toBe(true);

    // Duplicate of seq 10
    expect(window.checkAndAdvance(10n).valid).toBe(false);

    // Packet older than 64-bit window
    expect(window.checkAndAdvance(100n).valid).toBe(true);
    // Highest is 100n. Window covers 37n..100n. Seq 15n should be expired.
    const expiredRes = window.checkAndAdvance(15n);
    expect(expiredRes.valid).toBe(false);
    expect(expiredRes.reason).toContain('expired');
  });

  it('should frame, encrypt, and dissect full STANAG 5516 tactical frames', () => {
    const framer = new TacticalPacketFramer();
    const key = new Uint8Array(32).fill(0x88);
    const payload = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]);

    const packet = framer.framePacket(payload, 0x02, key, 0x12345678, 1n);
    expect(packet.length).toBe(18 + 12 + payload.length + 16);

    const dissected = framer.dissectAndVerify(packet, key);
    expect(dissected.authValid).toBe(true);
    expect(dissected.replayStatus).toBe('ACCEPTED');
    expect(dissected.header.sequenceNumber).toBe(1n);
    expect(dissected.header.msgType).toBe(0x02);
    expect(Array.from(dissected.plaintext!)).toEqual(Array.from(payload));

    // Replay same packet
    const replayed = framer.dissectAndVerify(packet, key);
    expect(replayed.replayStatus).toBe('REPLAY_REJECTED');
  });
});
