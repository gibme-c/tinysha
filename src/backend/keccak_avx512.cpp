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
// Key instructions used:
//   - VPROLVQ: variable 64-bit rotate for rho step (replaces 48 scalar shift/or ops)
//   - VPTERNLOGQ: ternary logic for chi step (a ^ (~b & c) in one instruction)
//   - VPERMQ / VPERMQVAR: lane permutation for chi row shifts
// Theta D-application uses vectorized XOR across 3 groups of 8 lanes.
// Pi uses scalar rearrangement through a temporary buffer.

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

        void keccak_f1600_avx512(uint64_t st[25])
        {
            // Rho rotation amounts indexed by source lane position.
            // _mm512_set_epi64 takes arguments in reverse order: (e7, e6, e5, e4, e3, e2, e1, e0)
            //
            // Rho offsets per lane [x + 5*y]:
            //   [0]=0   [1]=1   [2]=62  [3]=28  [4]=27  [5]=36  [6]=44  [7]=6
            //   [8]=55  [9]=20  [10]=3  [11]=10 [12]=43 [13]=25 [14]=39 [15]=41
            //   [16]=45 [17]=15 [18]=21 [19]=8  [20]=18 [21]=2  [22]=61 [23]=56
            //   [24]=14
            const __m512i rho_0 = _mm512_set_epi64(6, 44, 36, 27, 28, 62, 1, 0);
            const __m512i rho_1 = _mm512_set_epi64(41, 39, 25, 43, 10, 3, 20, 55);
            const __m512i rho_2 = _mm512_set_epi64(56, 61, 2, 18, 8, 21, 15, 45);

            // Chi row-shift indices: circular shift by +1 and +2 within 5-element rows.
            // Positions 5-7 are identity (unused but must not alias 0-4).
            const __m512i chi_s1 = _mm512_set_epi64(7, 6, 5, 0, 4, 3, 2, 1);
            const __m512i chi_s2 = _mm512_set_epi64(7, 6, 5, 1, 0, 4, 3, 2);

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

                // D[x] = C[(x+4)%5] ^ rotl(C[(x+1)%5], 1)
                uint64_t D[5];
                D[0] = C[4] ^ ((C[1] << 1) | (C[1] >> 63));
                D[1] = C[0] ^ ((C[2] << 1) | (C[2] >> 63));
                D[2] = C[1] ^ ((C[3] << 1) | (C[3] >> 63));
                D[3] = C[2] ^ ((C[4] << 1) | (C[4] >> 63));
                D[4] = C[3] ^ ((C[0] << 1) | (C[0] >> 63));

                // Apply D using AVX-512 XOR (3 vectors for lanes 0-23, scalar for lane 24)
                // D pattern repeats mod 5 across lane indices
                __m512i vd_0 = _mm512_set_epi64(
                    static_cast<long long>(D[2]),
                    static_cast<long long>(D[1]),
                    static_cast<long long>(D[0]),
                    static_cast<long long>(D[4]),
                    static_cast<long long>(D[3]),
                    static_cast<long long>(D[2]),
                    static_cast<long long>(D[1]),
                    static_cast<long long>(D[0]));
                __m512i s0 = _mm512_xor_si512(_mm512_loadu_si512(st), vd_0);

                __m512i vd_1 = _mm512_set_epi64(
                    static_cast<long long>(D[0]),
                    static_cast<long long>(D[4]),
                    static_cast<long long>(D[3]),
                    static_cast<long long>(D[2]),
                    static_cast<long long>(D[1]),
                    static_cast<long long>(D[0]),
                    static_cast<long long>(D[4]),
                    static_cast<long long>(D[3]));
                __m512i s1 = _mm512_xor_si512(_mm512_loadu_si512(st + 8), vd_1);

                __m512i vd_2 = _mm512_set_epi64(
                    static_cast<long long>(D[3]),
                    static_cast<long long>(D[2]),
                    static_cast<long long>(D[1]),
                    static_cast<long long>(D[0]),
                    static_cast<long long>(D[4]),
                    static_cast<long long>(D[3]),
                    static_cast<long long>(D[2]),
                    static_cast<long long>(D[1]));
                __m512i s2 = _mm512_xor_si512(_mm512_loadu_si512(st + 16), vd_2);

                uint64_t s24 = st[24] ^ D[4];

                // === Rho (VPROLVQ — variable 64-bit rotate) ===
                s0 = _mm512_rolv_epi64(s0, rho_0);
                s1 = _mm512_rolv_epi64(s1, rho_1);
                s2 = _mm512_rolv_epi64(s2, rho_2);
                s24 = (s24 << 14) | (s24 >> 50); // lane 24: rho=14

                // === Pi (scalar rearrangement via temporary buffer) ===
                // Store rotated lanes to aligned temp, then scatter to pi destinations.
                // Pi inverse: dst[d] = src[pi_inv[d]]
                alignas(64) uint64_t tmp[32]; // extra padding for aligned stores
                _mm512_store_si512(tmp, s0);
                _mm512_store_si512(tmp + 8, s1);
                _mm512_store_si512(tmp + 16, s2);
                tmp[24] = s24;

                st[0] = tmp[0];
                st[1] = tmp[6];
                st[2] = tmp[12];
                st[3] = tmp[18];
                st[4] = tmp[24];
                st[5] = tmp[3];
                st[6] = tmp[9];
                st[7] = tmp[10];
                st[8] = tmp[16];
                st[9] = tmp[22];
                st[10] = tmp[1];
                st[11] = tmp[7];
                st[12] = tmp[13];
                st[13] = tmp[19];
                st[14] = tmp[20];
                st[15] = tmp[4];
                st[16] = tmp[5];
                st[17] = tmp[11];
                st[18] = tmp[17];
                st[19] = tmp[23];
                st[20] = tmp[2];
                st[21] = tmp[8];
                st[22] = tmp[14];
                st[23] = tmp[15];
                st[24] = tmp[21];

                // === Chi (VPTERNLOGQ per row) ===
                // For each 5-lane row: new[x] = old[x] ^ (~old[(x+1)%5] & old[(x+2)%5])
                // VPTERNLOGQ(a, b, c, 0x78) = a ^ (~b & c)
                // Load row, create +1 and +2 circular shifts, apply ternary logic,
                // masked store (5 of 8 lanes).
                for (int y = 0; y < 25; y += 5)
                {
                    __m512i row = (y < 20) ? _mm512_loadu_si512(st + y) : _mm512_maskz_loadu_epi64(0x1F, st + y);

                    __m512i row1 = _mm512_permutexvar_epi64(chi_s1, row);
                    __m512i row2 = _mm512_permutexvar_epi64(chi_s2, row);
                    row = _mm512_ternarylogic_epi64(row, row1, row2, 0xD2);

                    _mm512_mask_storeu_epi64(st + y, 0x1F, row);
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
