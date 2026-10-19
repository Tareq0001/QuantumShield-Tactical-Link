#include "ntt_lattice_core.hpp"

namespace quantumshield {
namespace lattice {

// Exact FIPS 203 powers of primitive 256th root of unity (zeta = 17 mod 3329) in bit-reversed order
static constexpr std::array<int16_t, 128> ZETAS = {{
  1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746,
  296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
  289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915,
  2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
  17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
  1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641,
  1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594,
  2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154
}};

int16_t montgomery_reduce(int32_t a) noexcept {
  int16_t t = static_cast<int16_t>(a * QINV);
  int32_t u = (a - static_cast<int32_t>(t) * KYBER_Q) >> 16;
  return static_cast<int16_t>(u);
}

int16_t barrett_reduce(int16_t a) noexcept {
  int32_t v = (static_cast<int32_t>(a) * 5) >> 14;
  int16_t t = static_cast<int16_t>(static_cast<int32_t>(a) - v * KYBER_Q);
  return t;
}

int16_t fqmul(int16_t a, int16_t b) noexcept {
  int32_t prod = (static_cast<int32_t>(a) * static_cast<int32_t>(b)) % KYBER_Q;
  return static_cast<int16_t>((prod + KYBER_Q) % KYBER_Q);
}

void ntt(int16_t r[KYBER_N]) noexcept {
  size_t k = 1;
  for (size_t len = 128; len >= 2; len >>= 1) {
    for (size_t start = 0; start < KYBER_N; start += 2 * len) {
      int16_t zeta = ZETAS[k++];
      for (size_t j = start; j < start + len; ++j) {
        int16_t t = fqmul(zeta, r[j + len]);
        r[j + len] = static_cast<int16_t>((((r[j] - t) % KYBER_Q) + KYBER_Q) % KYBER_Q);
        r[j] = static_cast<int16_t>((r[j] + t) % KYBER_Q);
      }
    }
  }
}

void inv_ntt(int16_t r[KYBER_N]) noexcept {
  size_t k = 127;
  for (size_t len = 2; len <= 128; len <<= 1) {
    for (size_t start = 0; start < KYBER_N; start += 2 * len) {
      int16_t zeta = ZETAS[k--];
      for (size_t j = start; j < start + len; ++j) {
        int16_t t = r[j];
        r[j] = static_cast<int16_t>((t + r[j + len]) % KYBER_Q);
        r[j + len] = static_cast<int16_t>((((zeta * (r[j + len] - t)) % KYBER_Q) + KYBER_Q) % KYBER_Q);
      }
    }
  }

  constexpr int16_t F_INV128 = 3303;
  for (size_t j = 0; j < KYBER_N; ++j) {
    r[j] = static_cast<int16_t>((((r[j] * F_INV128) % KYBER_Q) + KYBER_Q) % KYBER_Q);
  }
}

void poly_pointwise_montgomery(
    int16_t c[KYBER_N],
    const int16_t a[KYBER_N],
    const int16_t b[KYBER_N]
) noexcept {
  for (size_t i = 0; i < 64; ++i) {
    int16_t gamma = ZETAS[64 + i];

    int32_t a0 = a[4 * i], a1 = a[4 * i + 1];
    int32_t b0 = b[4 * i], b1 = b[4 * i + 1];
    c[4 * i] = static_cast<int16_t>((((a0 * b0 + a1 * b1 * gamma) % KYBER_Q) + KYBER_Q) % KYBER_Q);
    c[4 * i + 1] = static_cast<int16_t>((((a0 * b1 + a1 * b0) % KYBER_Q) + KYBER_Q) % KYBER_Q);

    int32_t a2 = a[4 * i + 2], a3 = a[4 * i + 3];
    int32_t b2 = b[4 * i + 2], b3 = b[4 * i + 3];
    c[4 * i + 2] = static_cast<int16_t>((((a2 * b2 - a3 * b3 * gamma) % KYBER_Q) + KYBER_Q) % KYBER_Q);
    c[4 * i + 3] = static_cast<int16_t>((((a2 * b3 + a3 * b2) % KYBER_Q) + KYBER_Q) % KYBER_Q);
  }
}

bool ntt_self_test() noexcept {
  int16_t original[KYBER_N];
  int16_t test_poly[KYBER_N];

  for (size_t i = 0; i < KYBER_N; ++i) {
    original[i] = static_cast<int16_t>((i * 13 + 7) % KYBER_Q);
    test_poly[i] = original[i];
  }

  ntt(test_poly);
  inv_ntt(test_poly);

  for (size_t i = 0; i < KYBER_N; ++i) {
    int16_t diff = static_cast<int16_t>(((test_poly[i] - original[i]) % KYBER_Q + KYBER_Q) % KYBER_Q);
    if (diff != 0) {
      return false;
    }
  }

  return true;
}

} // namespace lattice
} // namespace quantumshield
