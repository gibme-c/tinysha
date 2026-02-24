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

// Keccak AVX2 backend — uses 256-bit SIMD for theta column parity and chi
// The 5x5 Keccak state doesn't map perfectly to 4-wide AVX2, but we can
// still get wins on theta (column XORs) and chi (row-wise AND-NOT).
// Compiled with -mavx2 (GCC/Clang) or /arch:AVX2 (MSVC)

#if defined(__x86_64__) || defined(_M_X64)

#include <cstdint>
#include <cstdlib>
#include <immintrin.h>

namespace tinysha
{
    namespace internal
    {

#if defined(__AVX2__) || (defined(_MSC_VER) && !defined(__clang__))

        static constexpr uint64_t RC_avx2[24] = {
            0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
            0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
            0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
            0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
            0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
            0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
        };

        static inline uint64_t rotl64(uint64_t x, int n)
        {
            return (x << n) | (x >> (64 - n));
        }

        // For Keccak, the AVX2 benefit comes from vectorizing the theta column
        // parity computation and the chi row operations. However, the rho+pi
        // step involves per-lane rotations by different amounts which AVX2
        // cannot do efficiently (no variable 64-bit rotate until AVX-512).
        // So we use AVX2 for theta and chi, scalar for rho+pi.
        void keccak_f1600_avx2(uint64_t st[25])
        {
            for (int round = 0; round < 24; ++round)
            {
                // === Theta ===
                // Compute column parities using AVX2: process 4 lanes at a time
                // C[x] = st[x] ^ st[x+5] ^ st[x+10] ^ st[x+15] ^ st[x+20]
                __m256i r0 = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(st)); // st[0..3]
                __m256i r5 = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(st + 5)); // st[5..8]
                __m256i r10 = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(st + 10));
                __m256i r15 = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(st + 15));
                __m256i r20 = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(st + 20));

                __m256i c04 =
                    _mm256_xor_si256(_mm256_xor_si256(r0, r5), _mm256_xor_si256(r10, _mm256_xor_si256(r15, r20)));
                // c04 contains C[0], C[1], C[2], C[3]
                // We still need C[4] scalar
                uint64_t C[5];
                _mm256_storeu_si256(reinterpret_cast<__m256i *>(C), c04);
                C[4] = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

                uint64_t D[5];
                D[0] = C[4] ^ rotl64(C[1], 1);
                D[1] = C[0] ^ rotl64(C[2], 1);
                D[2] = C[1] ^ rotl64(C[3], 1);
                D[3] = C[2] ^ rotl64(C[4], 1);
                D[4] = C[3] ^ rotl64(C[0], 1);

                // Apply D[x] to all rows — vectorize with AVX2
                __m256i vd04 = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(D)); // D[0..3]
                _mm256_storeu_si256(
                    reinterpret_cast<__m256i *>(st),
                    _mm256_xor_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i *>(st)), vd04));
                st[4] ^= D[4];
                _mm256_storeu_si256(
                    reinterpret_cast<__m256i *>(st + 5),
                    _mm256_xor_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i *>(st + 5)), vd04));
                st[9] ^= D[4];
                _mm256_storeu_si256(
                    reinterpret_cast<__m256i *>(st + 10),
                    _mm256_xor_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i *>(st + 10)), vd04));
                st[14] ^= D[4];
                _mm256_storeu_si256(
                    reinterpret_cast<__m256i *>(st + 15),
                    _mm256_xor_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i *>(st + 15)), vd04));
                st[19] ^= D[4];
                _mm256_storeu_si256(
                    reinterpret_cast<__m256i *>(st + 20),
                    _mm256_xor_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i *>(st + 20)), vd04));
                st[24] ^= D[4];

                // === Rho + Pi (scalar — per-lane variable rotations) ===
                uint64_t t = st[1], tmp;
                tmp = st[10];
                st[10] = rotl64(t, 1);
                t = tmp;
                tmp = st[7];
                st[7] = rotl64(t, 3);
                t = tmp;
                tmp = st[11];
                st[11] = rotl64(t, 6);
                t = tmp;
                tmp = st[17];
                st[17] = rotl64(t, 10);
                t = tmp;
                tmp = st[18];
                st[18] = rotl64(t, 15);
                t = tmp;
                tmp = st[3];
                st[3] = rotl64(t, 21);
                t = tmp;
                tmp = st[5];
                st[5] = rotl64(t, 28);
                t = tmp;
                tmp = st[16];
                st[16] = rotl64(t, 36);
                t = tmp;
                tmp = st[8];
                st[8] = rotl64(t, 45);
                t = tmp;
                tmp = st[21];
                st[21] = rotl64(t, 55);
                t = tmp;
                tmp = st[24];
                st[24] = rotl64(t, 2);
                t = tmp;
                tmp = st[4];
                st[4] = rotl64(t, 14);
                t = tmp;
                tmp = st[15];
                st[15] = rotl64(t, 27);
                t = tmp;
                tmp = st[23];
                st[23] = rotl64(t, 41);
                t = tmp;
                tmp = st[19];
                st[19] = rotl64(t, 56);
                t = tmp;
                tmp = st[13];
                st[13] = rotl64(t, 8);
                t = tmp;
                tmp = st[12];
                st[12] = rotl64(t, 25);
                t = tmp;
                tmp = st[2];
                st[2] = rotl64(t, 43);
                t = tmp;
                tmp = st[20];
                st[20] = rotl64(t, 62);
                t = tmp;
                tmp = st[14];
                st[14] = rotl64(t, 18);
                t = tmp;
                tmp = st[22];
                st[22] = rotl64(t, 39);
                t = tmp;
                tmp = st[9];
                st[9] = rotl64(t, 61);
                t = tmp;
                tmp = st[6];
                st[6] = rotl64(t, 20);
                t = tmp;
                st[1] = rotl64(t, 44);

                // === Chi (scalar per row — 5-wide doesn't fit 4-wide AVX2 cleanly) ===
                for (int y = 0; y < 25; y += 5)
                {
                    uint64_t t0 = st[y], t1 = st[y + 1], t2 = st[y + 2], t3 = st[y + 3], t4 = st[y + 4];
                    st[y + 0] = t0 ^ (~t1 & t2);
                    st[y + 1] = t1 ^ (~t2 & t3);
                    st[y + 2] = t2 ^ (~t3 & t4);
                    st[y + 3] = t3 ^ (~t4 & t0);
                    st[y + 4] = t4 ^ (~t0 & t1);
                }

                // === Iota ===
                st[0] ^= RC_avx2[round];
            }

            _mm256_zeroupper();
        }

#else
        void keccak_f1600_avx2(uint64_t[25])
        {
            // This stub should never be called — dispatch must not select
            // the AVX2 backend when AVX2 is unavailable at compile time.
            std::abort();
        }
#endif

    } // namespace internal
} // namespace tinysha

#endif // x86_64
