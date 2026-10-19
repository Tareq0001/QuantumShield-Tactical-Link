# QuantumShield — Post-Quantum Cryptography & Tactical Data Link Suite

[![Live Demo](https://img.shields.io/badge/Live_PQC_Suite-Tareq0001.github.io-purple?style=for-the-badge&logo=github)](https://tareq0001.github.io/QuantumShield-Tactical-Link/)
[![NIST Standard](https://img.shields.io/badge/NIST_PQC-FIPS_203_ML--KEM_%7C_FIPS_204_ML--DSA-blue?style=for-the-badge)](https://tareq0001.github.io/QuantumShield-Tactical-Link/)
[![Data Link](https://img.shields.io/badge/Tactical_Link-STANAG_5516_%7C_Link--16-emerald?style=for-the-badge)](https://tareq0001.github.io/QuantumShield-Tactical-Link/)

> **A mission-critical Post-Quantum Cryptography (PQC) and Military Tactical Data Link (Link-16 / STANAG 5516) cybersecurity suite. Implements NIST FIPS 203 (ML-KEM / CRYSTALS-Kyber) lattice key encapsulation, NIST FIPS 204 (ML-DSA / CRYSTALS-Dilithium) quantum-resistant signatures, J-Series tactical message framing (J2.2, J3.5, J12.0), Fast Frequency Hopping (FHSS) anti-jamming spectrogram, and interactive Shor's quantum cryptanalysis sandbox.**

---

## ⚡ Core Cryptographic & Tactical Data Link Capabilities

1. **NIST Post-Quantum Cryptographic Algorithms (FIPS 203 & 204)**
   - **ML-KEM-768 (Kyber):** Module Learning With Errors (M-LWE) key encapsulation delivering Category 3 (192-bit quantum security).
   - **ML-DSA-65 (Dilithium):** High-throughput digital signature algorithm verifying tactical message provenance against forgery.
   - Interactive 3-stage visual handshake: KeyGen $\rightarrow$ Encapsulation $\rightarrow$ Decapsulation establishing forward-secret AES-256-GCM symmetric session keys.

2. **Link-16 / STANAG 5516 Tactical Message Dissector**
   - **J2.2 Air PPLI:** Precise Participant Location and Identification broadcast with Mode 5 IFF.
   - **J3.5 Surface-to-Air Threat:** SAM site coordinates, radar frequency band, and threat radius.
   - **J12.0 Mission Assignment:** Tactical air combat vector tasking with target track correlation.
   - Real-time packet hex inspector dissecting preamble, security headers, cryptographic sync words, and Reed-Solomon forward error correction (FEC).

3. **Fast Frequency Hopping Spread Spectrum (FHSS) Anti-Jamming Spectrogram**
   - 76,923 hops/sec pseudorandom carrier agile frequency synthesizer operating across the 969 - 1206 MHz tactical band.
   - Real-time spectral waterfall visualization demonstrating Low Probability of Intercept / Detection (LPI/LPD).

4. **Quantum Cryptanalysis Simulation Sandbox**
   - Side-by-side benchmark contrasting Shor's polynomial-time factoring of classical RSA-2048 with the exponential hardness of the Shortest Vector Problem (SVP) in high-dimensional lattices.

---

## 🛠️ Architecture & Tech Stack

- **Cryptographic Foundations:** Module-Lattice LWE, SHA3-256 / SHAKE-256 Keccak Sponge Functions, AES-256-GCM.
- **Visuals & Canvas:** Real-time FHSS spectrum waterfall rendering (60 FPS), interactive hex packet dissector.
- **Audio:** Web Audio API Frequency Shift Keying (FSK) data burst synthesis.
- **UI:** Tactile glassmorphism crypto operations deck, bilingual English/Arabic interface.

---

## 🚀 Live Deployment

- **Online PQC Suite:** [https://tareq0001.github.io/QuantumShield-Tactical-Link/](https://tareq0001.github.io/QuantumShield-Tactical-Link/)
- **Author:** Eng. Tareq Aboushi (Tareq0001)
- **Standards:** NIST FIPS 203/204 | STANAG 5516 | Link-16
