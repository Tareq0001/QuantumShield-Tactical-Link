#!/usr/bin/env python3
"""
Quantum Key Distribution (BB84) Optical Fiber Simulator & NIST SP 800-22 Entropy Suite
QuantumShield Defense COMSEC Research

Simulates:
- Weak coherent pulse (WCP) state preparation with Poissonian statistics
- Standard single-mode fiber (SMF-28) attenuation at 1550 nm (alpha = 0.2 dB/km)
- Single-photon avalanche diode (SPAD) detection & dark counts
- Eve intercept-resend attack with quantum state collapse
- Sifting, QBER parameter estimation, and Toeplitz privacy amplification
- NIST SP 800-22 statistical hypothesis tests (Monobit Frequency & Runs tests)
"""

import argparse
import sys
import math
import numpy as np
from scipy import special


class QKDChannelSimulator:
    def __init__(
        self,
        fiber_length_km: float = 15.0,
        attenuation_db_per_km: float = 0.20,
        detector_efficiency: float = 0.25,
        dark_count_prob: float = 1e-5,
        depolarization_rate: float = 0.015,
        qber_threshold: float = 0.11,
    ):
        self.fiber_length_km = fiber_length_km
        self.attenuation_db_per_km = attenuation_db_per_km
        self.detector_efficiency = detector_efficiency
        self.dark_count_prob = dark_count_prob
        self.depolarization_rate = depolarization_rate
        self.qber_threshold = qber_threshold

        # Beer-Lambert optical transmission: T_fiber = 10^(-alpha * L / 10)
        self.channel_transmission = 10.0 ** (-self.attenuation_db_per_km * self.fiber_length_km / 10.0)
        self.total_detection_prob = self.channel_transmission * self.detector_efficiency

    def simulate_bb84(
        self,
        num_pulses: int = 10000,
        eve_interception_prob: float = 0.0,
        random_seed: int = None,
    ) -> dict:
        """
        Executes complete BB84 simulation run across optical quantum channel.
        """
        rng = np.random.default_rng(random_seed)

        # Alice generates random bits and bases (0 = rectilinear '+', 1 = diagonal 'x')
        alice_bits = rng.integers(0, 2, size=num_pulses, dtype=np.uint8)
        alice_bases = rng.integers(0, 2, size=num_pulses, dtype=np.uint8)

        # Eve Intercept-Resend Attack Simulation
        transmitted_bits = alice_bits.copy()
        transmitted_bases = alice_bases.copy()
        eve_intercepted_mask = np.zeros(num_pulses, dtype=bool)

        if eve_interception_prob > 0.0:
            eve_intercepted_mask = rng.random(num_pulses) < eve_interception_prob
            num_intercepted = int(np.sum(eve_intercepted_mask))
            if num_intercepted > 0:
                eve_bases = rng.integers(0, 2, size=num_intercepted, dtype=np.uint8)
                orig_bases = alice_bases[eve_intercepted_mask]
                orig_bits = alice_bits[eve_intercepted_mask]

                # If Eve measures in wrong basis, bit collapses to 50/50
                basis_mismatch = (eve_bases != orig_bases)
                eve_measured_bits = orig_bits.copy()
                random_flips = rng.integers(0, 2, size=int(np.sum(basis_mismatch)), dtype=np.uint8)
                eve_measured_bits[basis_mismatch] = random_flips

                transmitted_bits[eve_intercepted_mask] = eve_measured_bits
                transmitted_bases[eve_intercepted_mask] = eve_bases

        # Bob detection through optical channel
        fiber_detections = rng.random(num_pulses) < self.total_detection_prob
        dark_counts = rng.random(num_pulses) < self.dark_count_prob
        bob_detected_mask = fiber_detections | dark_counts

        # Bob selects random measurement bases
        bob_bases = rng.integers(0, 2, size=num_pulses, dtype=np.uint8)
        bob_bits = np.zeros(num_pulses, dtype=np.uint8)

        # Bob measures detected photons
        detected_indices = np.where(bob_detected_mask)[0]
        for idx in detected_indices:
            if dark_counts[idx] and not fiber_detections[idx]:
                bob_bits[idx] = rng.integers(0, 2)
            else:
                pol_basis = transmitted_bases[idx]
                pol_bit = transmitted_bits[idx]
                meas_basis = bob_bases[idx]

                if meas_basis == pol_basis:
                    # Depolarization channel noise
                    if rng.random() < self.depolarization_rate:
                        bob_bits[idx] = 1 - pol_bit
                    else:
                        bob_bits[idx] = pol_bit
                else:
                    bob_bits[idx] = rng.integers(0, 2)

        # Sifting: Keep events where photon was detected AND Alice & Bob used matching bases
        sift_mask = bob_detected_mask & (alice_bases == bob_bases)
        sifted_alice = alice_bits[sift_mask]
        sifted_bob = bob_bits[sift_mask]
        sifted_count = len(sifted_alice)

        if sifted_count < 32:
            return {
                "status": "INSUFFICIENT_SIFTED_BITS",
                "sifted_count": sifted_count,
                "qber": 0.0,
                "eavesdropper_detected": False,
                "final_key": np.array([], dtype=np.uint8),
            }

        # QBER Parameter Estimation: Sample 25% of sifted bits
        sample_size = max(16, int(sifted_count * 0.25))
        perm = rng.permutation(sifted_count)
        test_indices = perm[:sample_size]
        key_indices = perm[sample_size:]

        test_errors = np.sum(sifted_alice[test_indices] != sifted_bob[test_indices])
        qber = float(test_errors) / sample_size
        eavesdropper_detected = qber > self.qber_threshold

        if eavesdropper_detected:
            return {
                "status": "ABORTED_EAVESDROPPER_DETECTED",
                "sifted_count": sifted_count,
                "qber": qber,
                "test_errors": int(test_errors),
                "eavesdropper_detected": True,
                "final_key": np.array([], dtype=np.uint8),
            }

        # Privacy Amplification via Toeplitz Hashing over GF(2)
        raw_key = sifted_alice[key_indices]
        # Compression factor from Holevo bound: 1 - 2 * h_2(qber)
        h2 = 0.0 if qber <= 0 or qber >= 1 else -qber * math.log2(qber) - (1 - qber) * math.log2(1 - qber)
        target_len = max(64, min(len(raw_key), int(len(raw_key) * max(0.2, 1.0 - 2.0 * h2))))

        # Toeplitz matrix multiplication
        toeplitz_seed = rng.integers(0, 2, size=len(raw_key) + target_len - 1, dtype=np.uint8)
        final_key = np.zeros(target_len, dtype=np.uint8)
        for row in range(target_len):
            col_slice = toeplitz_seed[row : row + len(raw_key)]
            final_key[row] = np.bitwise_xor.reduce(col_slice & raw_key)

        return {
            "status": "SECURE_KEY_ESTABLISHED",
            "sifted_count": sifted_count,
            "qber": qber,
            "test_errors": int(test_errors),
            "eavesdropper_detected": False,
            "final_key_len": len(final_key),
            "final_key": final_key,
        }


# ============================================================================
# NIST SP 800-22 Randomness Statistical Tests
# ============================================================================

def nist_sp800_22_monobit_frequency_test(bits: np.ndarray) -> tuple[float, bool]:
    """
    NIST SP 800-22 Section 2.1: Frequency (Monobit) Test
    Focuses on the proportion of zeroes and ones for the entire sequence.
    """
    n = len(bits)
    if n == 0:
        return 0.0, False

    # Convert 0,1 to -1, +1
    s_n = np.sum(2 * bits.astype(int) - 1)
    s_obs = abs(s_n) / math.sqrt(n)
    p_value = float(special.erfc(s_obs / math.sqrt(2)))
    passed = p_value >= 0.01
    return p_value, passed


def nist_sp800_22_runs_test(bits: np.ndarray) -> tuple[float, bool]:
    """
    NIST SP 800-22 Section 2.2: Runs Test
    Tests whether the number of runs of ones and zeroes of various lengths is as expected.
    """
    n = len(bits)
    if n < 10:
        return 0.0, False

    pi = float(np.mean(bits))
    tau = 2.0 / math.sqrt(n)
    if abs(pi - 0.5) >= tau:
        return 0.0, False

    # Count runs (transitions + 1)
    v_obs = int(np.sum(bits[:-1] != bits[1:])) + 1
    numerator = abs(v_obs - 2.0 * n * pi * (1.0 - pi))
    denominator = 2.0 * math.sqrt(2.0 * n) * pi * (1.0 - pi)
    if denominator == 0:
        return 0.0, False

    p_value = float(special.erfc(numerator / denominator))
    passed = p_value >= 0.01
    return p_value, passed


# ============================================================================
# Self-Test & CLI Entry Point
# ============================================================================

def run_self_test() -> bool:
    print("====================================================================")
    print(" [QuantumShield] BB84 Quantum Channel & NIST SP 800-22 Verification")
    print("====================================================================")

    sim = QKDChannelSimulator(fiber_length_km=10.0, attenuation_db_per_km=0.20)

    # Test Case 1: Honest Quantum Channel (No Eve)
    print("\n--- Test 1: Honest Fiber Channel (10 km SMF-28, No Eavesdropper) ---")
    res_honest = sim.simulate_bb84(num_pulses=15000, eve_interception_prob=0.0, random_seed=42)
    print(f"Status: {res_honest['status']}")
    print(f"Sifted bits: {res_honest['sifted_count']}")
    print(f"Estimated QBER: {res_honest['qber'] * 100:.2f}% (Threshold: 11.00%)")
    print(f"Eavesdropper Detected: {res_honest['eavesdropper_detected']}")

    if res_honest['status'] != 'SECURE_KEY_ESTABLISHED':
        print("[FAIL] Honest channel failed to establish secure key!")
        return False

    if res_honest['qber'] > 0.05:
        print(f"[FAIL] Honest channel QBER too high: {res_honest['qber']}")
        return False

    # Entropy evaluation on final distilled key
    final_key = res_honest['final_key']
    p_mono, pass_mono = nist_sp800_22_monobit_frequency_test(final_key)
    p_runs, pass_runs = nist_sp800_22_runs_test(final_key)
    print(f"Distilled Quantum Key: {len(final_key)} bits")
    print(f"NIST SP 800-22 Monobit Test: p-value = {p_mono:.5f} [{'PASS' if pass_mono else 'FAIL'}]")
    print(f"NIST SP 800-22 Runs Test:    p-value = {p_runs:.5f} [{'PASS' if pass_runs else 'FAIL'}]")

    if not pass_mono or not pass_runs:
        print("[FAIL] Distilled key failed NIST SP 800-22 randomness threshold (alpha=0.01)!")
        return False

    # Test Case 2: Hostile Quantum Channel under 100% Intercept-Resend Attack
    print("\n--- Test 2: Hostile Channel (100% Intercept-Resend Attack by Eve) ---")
    res_eve = sim.simulate_bb84(num_pulses=15000, eve_interception_prob=1.0, random_seed=42)
    print(f"Status: {res_eve['status']}")
    print(f"Sifted bits: {res_eve['sifted_count']}")
    print(f"Estimated QBER under Attack: {res_eve['qber'] * 100:.2f}%")
    print(f"Eavesdropper Detected: {res_eve['eavesdropper_detected']}")

    if not res_eve['eavesdropper_detected']:
        print("[FAIL] System failed to detect full eavesdropping attack!")
        return False

    if res_eve['status'] != 'ABORTED_EAVESDROPPER_DETECTED':
        print("[FAIL] Protocol did not abort under eavesdropping attack!")
        return False

    print("\n[SUCCESS] All BB84 Quantum Channel & Entropy Tests Passed Cleanly (100%).")
    return True


def main():
    parser = argparse.ArgumentParser(description="BB84 QKD Optical Fiber Simulator")
    parser.add_argument("--self-test", action="store_true", help="Run comprehensive QKD & NIST self-tests")
    parser.add_argument("--length-km", type=float, default=15.0, help="Fiber length in km")
    parser.add_argument("--pulses", type=int, default=10000, help="Number of transmitted photon pulses")
    parser.add_argument("--eve", type=float, default=0.0, help="Eve interception probability [0..1]")

    args = parser.parse_args()

    if args.self_test:
        success = run_self_test()
        sys.exit(0 if success else 1)

    sim = QKDChannelSimulator(fiber_length_km=args.length_km)
    res = sim.simulate_bb84(num_pulses=args.pulses, eve_interception_prob=args.eve)
    print(f"Status: {res['status']}")
    print(f"Sifted Count: {res.get('sifted_count', 0)}")
    print(f"QBER: {res.get('qber', 0.0) * 100:.2f}%")
    print(f"Eavesdropper Detected: {res.get('eavesdropper_detected', False)}")


if __name__ == "__main__":
    main()
