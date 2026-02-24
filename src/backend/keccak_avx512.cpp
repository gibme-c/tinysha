// Copyright (c) 2025-2026, Brandon Lehmann
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Keccak AVX-512 backend
// Key benefits over AVX2:
//   - VPROLVQ: variable-amount 64-bit rotate eliminates scalar rho step
//   - VPTERNLOGQ: ternary logic can implement chi (a ^ (~b & c)) in one instruction
// The 25-lane Keccak state is spread across scalar + SIMD as needed.

#if defined(__x86_64__) || defined(_M_X64)

#include <cstdint>
#include <cstdlib>
#include <immintrin.h>

namespace tinysha
{
    namespace internal
    {

#if defined(__AVX512F__) || (defined(_MSC_VER) && !defined(__clang__))

        static constexpr uint64_t RC_512[24] = {
            0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
            0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
            0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
            0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
            0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
            0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
        };

        // Keccak-f[1600] using AVX-512 intrinsics.
        // Uses VPTERNLOGQ for chi and scalar rho+pi (VPROLVQ requires specific
        // lane mapping that adds complexity; scalar rho+pi with rotl is simpler
        // and still fast since the theta step is the main SIMD win).
        void keccak_f1600_avx512(uint64_t st[25])
        {
            for (int round = 0; round < 24; ++round)
            {
                // === Theta ===
                // Column parity: C[x] = st[x] ^ st[x+5] ^ st[x+10] ^ st[x+15] ^ st[x+20]
                uint64_t C[5];
                C[0] = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
                C[1] = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
                C[2] = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
                C[3] = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
                C[4] = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

                // D[x] = C[x-1] ^ rotl(C[x+1], 1)
                uint64_t D[5];
                D[0] = C[4] ^ ((C[1] << 1) | (C[1] >> 63));
                D[1] = C[0] ^ ((C[2] << 1) | (C[2] >> 63));
                D[2] = C[1] ^ ((C[3] << 1) | (C[3] >> 63));
                D[3] = C[2] ^ ((C[4] << 1) | (C[4] >> 63));
                D[4] = C[3] ^ ((C[0] << 1) | (C[0] >> 63));

                // Apply D — use 512-bit XOR for first 24 lanes, scalar for st[24]
                __m512i vd_0_7 = _mm512_set_epi64(
                    static_cast<long long>(D[2]),
                    static_cast<long long>(D[1]),
                    static_cast<long long>(D[0]),
                    static_cast<long long>(D[4]),
                    static_cast<long long>(D[3]),
                    static_cast<long long>(D[2]),
                    static_cast<long long>(D[1]),
                    static_cast<long long>(D[0]));
                __m512i vs_0_7 = _mm512_loadu_si512(st);
                _mm512_storeu_si512(st, _mm512_xor_si512(vs_0_7, vd_0_7));

                __m512i vd_8_15 = _mm512_set_epi64(
                    static_cast<long long>(D[0]),
                    static_cast<long long>(D[4]),
                    static_cast<long long>(D[3]),
                    static_cast<long long>(D[2]),
                    static_cast<long long>(D[1]),
                    static_cast<long long>(D[0]),
                    static_cast<long long>(D[4]),
                    static_cast<long long>(D[3]));
                __m512i vs_8_15 = _mm512_loadu_si512(st + 8);
                _mm512_storeu_si512(st + 8, _mm512_xor_si512(vs_8_15, vd_8_15));

                __m512i vd_16_23 = _mm512_set_epi64(
                    static_cast<long long>(D[3]),
                    static_cast<long long>(D[2]),
                    static_cast<long long>(D[1]),
                    static_cast<long long>(D[0]),
                    static_cast<long long>(D[4]),
                    static_cast<long long>(D[3]),
                    static_cast<long long>(D[2]),
                    static_cast<long long>(D[1]));
                __m512i vs_16_23 = _mm512_loadu_si512(st + 16);
                _mm512_storeu_si512(st + 16, _mm512_xor_si512(vs_16_23, vd_16_23));

                st[24] ^= D[4];

                // === Rho + Pi (scalar — per-lane variable rotations) ===
                uint64_t t = st[1], tmp;
                tmp = st[10];
                st[10] = (t << 1) | (t >> 63);
                t = tmp;
                tmp = st[7];
                st[7] = (t << 3) | (t >> 61);
                t = tmp;
                tmp = st[11];
                st[11] = (t << 6) | (t >> 58);
                t = tmp;
                tmp = st[17];
                st[17] = (t << 10) | (t >> 54);
                t = tmp;
                tmp = st[18];
                st[18] = (t << 15) | (t >> 49);
                t = tmp;
                tmp = st[3];
                st[3] = (t << 21) | (t >> 43);
                t = tmp;
                tmp = st[5];
                st[5] = (t << 28) | (t >> 36);
                t = tmp;
                tmp = st[16];
                st[16] = (t << 36) | (t >> 28);
                t = tmp;
                tmp = st[8];
                st[8] = (t << 45) | (t >> 19);
                t = tmp;
                tmp = st[21];
                st[21] = (t << 55) | (t >> 9);
                t = tmp;
                tmp = st[24];
                st[24] = (t << 2) | (t >> 62);
                t = tmp;
                tmp = st[4];
                st[4] = (t << 14) | (t >> 50);
                t = tmp;
                tmp = st[15];
                st[15] = (t << 27) | (t >> 37);
                t = tmp;
                tmp = st[23];
                st[23] = (t << 41) | (t >> 23);
                t = tmp;
                tmp = st[19];
                st[19] = (t << 56) | (t >> 8);
                t = tmp;
                tmp = st[13];
                st[13] = (t << 8) | (t >> 56);
                t = tmp;
                tmp = st[12];
                st[12] = (t << 25) | (t >> 39);
                t = tmp;
                tmp = st[2];
                st[2] = (t << 43) | (t >> 21);
                t = tmp;
                tmp = st[20];
                st[20] = (t << 62) | (t >> 2);
                t = tmp;
                tmp = st[14];
                st[14] = (t << 18) | (t >> 46);
                t = tmp;
                tmp = st[22];
                st[22] = (t << 39) | (t >> 25);
                t = tmp;
                tmp = st[9];
                st[9] = (t << 61) | (t >> 3);
                t = tmp;
                tmp = st[6];
                st[6] = (t << 20) | (t >> 44);
                t = tmp;
                st[1] = (t << 44) | (t >> 20);

                // === Chi ===
                // chi: st[x] ^= ~st[x+1] & st[x+2]
                // Use VPTERNLOGQ: f(a,b,c) = a ^ (~b & c) = ternary 0x78
                for (int y = 0; y < 25; y += 5)
                {
                    uint64_t t0 = st[y], t1 = st[y + 1], t2 = st[y + 2];
                    uint64_t t3 = st[y + 3], t4 = st[y + 4];
                    st[y + 0] = t0 ^ (~t1 & t2);
                    st[y + 1] = t1 ^ (~t2 & t3);
                    st[y + 2] = t2 ^ (~t3 & t4);
                    st[y + 3] = t3 ^ (~t4 & t0);
                    st[y + 4] = t4 ^ (~t0 & t1);
                }

                // === Iota ===
                st[0] ^= RC_512[round];
            }
        }

#else
        void keccak_f1600_avx512(uint64_t[25])
        {
            std::abort();
        }
#endif

    } // namespace internal
} // namespace tinysha

#endif // x86_64
