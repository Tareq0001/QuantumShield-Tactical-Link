#include "ntt_lattice_core.hpp"

namespace quantumshield {
namespace lattice {

// Precomputed powers of primitive 256th root of unity (zeta = 17) in bit-reversed order, Montgomery form
static constexpr std::array<int16_t, 128> ZETAS = {{
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
  1092, -1386, 1121, -1105, 1382, -1186, 1136, 1165
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
  return montgomery_reduce(static_cast<int32_t>(a) * static_cast<int32_t>(b));
}

void ntt(int16_t r[KYBER_N]) noexcept {
  size_t k = 1;
  for (size_t len = 128; len >= 2; len >>= 1) {
    for (size_t start = 0; start < KYBER_N; start += 2 * len) {
      int16_t zeta = ZETAS[k++];
      for (size_t j = start; j < start + len; ++j) {
        int16_t t = fqmul(zeta, r[j + len]);
        r[j + len] = static_cast<int16_t>(r[j] - t);
        r[j] = static_cast<int16_t>(r[j] + t);
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
        r[j] = barrett_reduce(static_cast<int16_t>(t + r[j + len]));
        r[j + len] = fqmul(zeta, static_cast<int16_t>(r[j + len] - t));
      }
    }
  }

  // Precomputed factor f = 3307 (128^-1 * R mod q)
  constexpr int16_t F_INV128 = 3307;
  for (size_t j = 0; j < KYBER_N; ++j) {
    r[j] = fqmul(r[j], F_INV128);
  }
}

static void poly_basemul_montgomery(
    int16_t r[2],
    const int16_t a[2],
    const int16_t b[2],
    int16_t zeta
) noexcept {
  int16_t a0 = a[0], a1 = a[1];
  int16_t b0 = b[0], b1 = b[1];

  r[0] = montgomery_reduce(
      static_cast<int32_t>(fqmul(a1, b1)) * zeta + static_cast<int32_t>(a0) * b0
  );
  r[1] = montgomery_reduce(
      static_cast<int32_t>(a0) * b1 + static_cast<int32_t>(a1) * b0
  );
}

void poly_pointwise_montgomery(
    int16_t c[KYBER_N],
    const int16_t a[KYBER_N],
    const int16_t b[KYBER_N]
) noexcept {
  for (size_t i = 0; i < 64; ++i) {
    int16_t zeta = ZETAS[64 + i];
    poly_basemul_montgomery(&c[4 * i], &a[4 * i], &b[4 * i], zeta);
    poly_basemul_montgomery(&c[4 * i + 2], &a[4 * i + 2], &b[4 * i + 2], static_cast<int16_t>(-zeta));
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
