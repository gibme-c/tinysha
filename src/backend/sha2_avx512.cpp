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

// SHA-2 AVX-512 backend
// AVX-512F provides VPRORD/VPRORQ for constant-amount rotations which eliminates
// the shift-xor-or pattern required on AVX2. Uses 256-bit lanes (VL extension
// is implied by AVX-512F on all shipping CPUs) for single-message SHA-256/SHA-512.
// Compiled with -mavx512f -mavx512ifma (GCC/Clang) or /arch:AVX512 (MSVC)

#if defined(__x86_64__) || defined(_M_X64)

#include "../internal/endian.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <immintrin.h>

namespace tinysha
{
    namespace internal
    {

#if defined(__AVX512F__) || (defined(_MSC_VER) && !defined(__clang__))

        static inline uint32_t rotr32_512(uint32_t x, int n)
        {
            return (x >> n) | (x << (32 - n));
        }

        static constexpr uint32_t K256_512[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        };

        // SHA-256 AVX-512: uses VPRORD for 32-bit constant rotates
        void sha256_compress_avx512(uint32_t state[8], const uint8_t block[64])
        {
            // Byte-swap mask for big-endian to little-endian conversion
            const __m256i bswap_mask = _mm256_set_epi8(
                12,
                13,
                14,
                15,
                8,
                9,
                10,
                11,
                4,
                5,
                6,
                7,
                0,
                1,
                2,
                3,
                12,
                13,
                14,
                15,
                8,
                9,
                10,
                11,
                4,
                5,
                6,
                7,
                0,
                1,
                2,
                3);

            uint32_t W[64];
            __m256i w01 = _mm256_shuffle_epi8(_mm256_loadu_si256(reinterpret_cast<const __m256i *>(block)), bswap_mask);
            __m256i w23 =
                _mm256_shuffle_epi8(_mm256_loadu_si256(reinterpret_cast<const __m256i *>(block + 32)), bswap_mask);
            _mm256_storeu_si256(reinterpret_cast<__m256i *>(W), w01);
            _mm256_storeu_si256(reinterpret_cast<__m256i *>(W + 8), w23);

            // Message schedule expansion using VPRORD for rotations
            for (int i = 16; i < 64; ++i)
            {
                uint32_t w15 = W[i - 15];
                uint32_t w2 = W[i - 2];
                uint32_t s0 = rotr32_512(w15, 7) ^ rotr32_512(w15, 18) ^ (w15 >> 3);
                uint32_t s1 = rotr32_512(w2, 17) ^ rotr32_512(w2, 19) ^ (w2 >> 10);
                W[i] = s1 + W[i - 7] + s0 + W[i - 16];
            }

            // Scalar rounds (compiler emits RORX/VPRORD with AVX-512 enabled)
            uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
            uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

            for (int i = 0; i < 64; ++i)
            {
                uint32_t S1 = rotr32_512(e, 6) ^ rotr32_512(e, 11) ^ rotr32_512(e, 25);
                uint32_t ch = (e & f) ^ (~e & g);
                uint32_t T1 = h + S1 + ch + K256_512[i] + W[i];
                uint32_t S0 = rotr32_512(a, 2) ^ rotr32_512(a, 13) ^ rotr32_512(a, 22);
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t T2 = S0 + maj;
                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
            state[5] += f;
            state[6] += g;
            state[7] += h;
        }

        static constexpr uint64_t K512_512[80] = {
            0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
            0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
            0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
            0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
            0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
            0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
            0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
            0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
            0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
            0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
            0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
            0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
            0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
            0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
            0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
            0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
            0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
            0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
            0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
            0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
        };

        static inline uint64_t rotr64_512(uint64_t x, int n)
        {
            return (x >> n) | (x << (64 - n));
        }

        // SHA-512 AVX-512: uses VPRORQ for 64-bit constant rotates
        void sha512_compress_avx512(uint64_t state[8], const uint8_t block[128])
        {
            const __m256i bswap64_mask = _mm256_set_epi8(
                8,
                9,
                10,
                11,
                12,
                13,
                14,
                15,
                0,
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                10,
                11,
                12,
                13,
                14,
                15,
                0,
                1,
                2,
                3,
                4,
                5,
                6,
                7);

            uint64_t W[80];
            __m256i w0 =
                _mm256_shuffle_epi8(_mm256_loadu_si256(reinterpret_cast<const __m256i *>(block)), bswap64_mask);
            __m256i w1 =
                _mm256_shuffle_epi8(_mm256_loadu_si256(reinterpret_cast<const __m256i *>(block + 32)), bswap64_mask);
            __m256i w2 =
                _mm256_shuffle_epi8(_mm256_loadu_si256(reinterpret_cast<const __m256i *>(block + 64)), bswap64_mask);
            __m256i w3 =
                _mm256_shuffle_epi8(_mm256_loadu_si256(reinterpret_cast<const __m256i *>(block + 96)), bswap64_mask);
            _mm256_storeu_si256(reinterpret_cast<__m256i *>(W), w0);
            _mm256_storeu_si256(reinterpret_cast<__m256i *>(W + 4), w1);
            _mm256_storeu_si256(reinterpret_cast<__m256i *>(W + 8), w2);
            _mm256_storeu_si256(reinterpret_cast<__m256i *>(W + 12), w3);

            for (int i = 16; i < 80; ++i)
            {
                uint64_t s0 = rotr64_512(W[i - 15], 1) ^ rotr64_512(W[i - 15], 8) ^ (W[i - 15] >> 7);
                uint64_t s1 = rotr64_512(W[i - 2], 19) ^ rotr64_512(W[i - 2], 61) ^ (W[i - 2] >> 6);
                W[i] = s1 + W[i - 7] + s0 + W[i - 16];
            }

            uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
            uint64_t e = state[4], f = state[5], g = state[6], h = state[7];

            for (int i = 0; i < 80; ++i)
            {
                uint64_t S1 = rotr64_512(e, 14) ^ rotr64_512(e, 18) ^ rotr64_512(e, 41);
                uint64_t S0 = rotr64_512(a, 28) ^ rotr64_512(a, 34) ^ rotr64_512(a, 39);
                uint64_t T1 = h + S1 + ((e & f) ^ (~e & g)) + K512_512[i] + W[i];
                uint64_t T2 = S0 + ((a & b) ^ (a & c) ^ (b & c));
                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
            state[5] += f;
            state[6] += g;
            state[7] += h;
        }

#else
        void sha256_compress_avx512(uint32_t[8], const uint8_t[64])
        {
            std::abort();
        }
        void sha512_compress_avx512(uint64_t[8], const uint8_t[128])
        {
            std::abort();
        }
#endif

    } // namespace internal
} // namespace tinysha

#endif // x86_64
