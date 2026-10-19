#ifndef NTT_LATTICE_CORE_HPP
#define NTT_LATTICE_CORE_HPP

#include <cstdint>
#include <cstddef>
#include <array>

namespace quantumshield {
namespace lattice {

constexpr int16_t KYBER_N = 256;
constexpr int16_t KYBER_Q = 3329;
constexpr int16_t MONTGOMERY_R = 2285; // 2^16 mod 3329
constexpr int16_t QINV = -3327;        // q^-1 mod 2^16

/**
 * Constant-time Montgomery reduction.
 * Computes a * R^-1 mod q, where R = 2^16.
 */
int16_t montgomery_reduce(int32_t a) noexcept;

/**
 * Constant-time Barrett reduction.
 * Reduces a mod q.
 */
int16_t barrett_reduce(int16_t a) noexcept;

/**
 * Constant-time Montgomery modular multiplication: (a * b) * R^-1 mod q.
 */
int16_t fqmul(int16_t a, int16_t b) noexcept;

/**
 * In-place Forward Number Theoretic Transform (NTT) for Kyber ring R_q.
 */
void ntt(int16_t r[KYBER_N]) noexcept;

/**
 * In-place Inverse Number Theoretic Transform (invNTT) for Kyber ring R_q.
 */
void inv_ntt(int16_t r[KYBER_N]) noexcept;

/**
 * Pointwise multiplication of two polynomials in NTT domain.
 */
void poly_pointwise_montgomery(
    int16_t c[KYBER_N],
    const int16_t a[KYBER_N],
    const int16_t b[KYBER_N]
) noexcept;

/**
 * Executes self-test verifying forward & inverse NTT reversibility.
 * Returns true if NTT roundtrip holds for all 256 coefficients.
 */
bool ntt_self_test() noexcept;

} // namespace lattice
} // namespace quantumshield

#endif // NTT_LATTICE_CORE_HPP
