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

#include "../internal/endian.h"

#include <cstdint>
#include <cstring>

namespace tinysha
{
    namespace internal
    {

        // SHA-256 round constants
        static constexpr uint32_t K256[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        };

        // SHA-512 round constants
        static constexpr uint64_t K512[80] = {
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

        static inline uint32_t rotr32(uint32_t x, int n)
        {
            return (x >> n) | (x << (32 - n));
        }

        static inline uint64_t rotr64(uint64_t x, int n)
        {
            return (x >> n) | (x << (64 - n));
        }

        static inline uint32_t Ch32(uint32_t x, uint32_t y, uint32_t z)
        {
            return (x & y) ^ (~x & z);
        }

        static inline uint32_t Maj32(uint32_t x, uint32_t y, uint32_t z)
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        static inline uint32_t Sigma0_256(uint32_t x)
        {
            return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
        }

        static inline uint32_t Sigma1_256(uint32_t x)
        {
            return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
        }

        static inline uint32_t sigma0_256(uint32_t x)
        {
            return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
        }

        static inline uint32_t sigma1_256(uint32_t x)
        {
            return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
        }

        static inline uint64_t Ch64(uint64_t x, uint64_t y, uint64_t z)
        {
            return (x & y) ^ (~x & z);
        }

        static inline uint64_t Maj64(uint64_t x, uint64_t y, uint64_t z)
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        static inline uint64_t Sigma0_512(uint64_t x)
        {
            return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
        }

        static inline uint64_t Sigma1_512(uint64_t x)
        {
            return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
        }

        static inline uint64_t sigma0_512(uint64_t x)
        {
            return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
        }

        static inline uint64_t sigma1_512(uint64_t x)
        {
            return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6);
        }

        // SHA-256 compression function: processes one 64-byte block
        void sha256_compress_portable(uint32_t state[8], const uint8_t block[64])
        {
            uint32_t W[64];
            for (int i = 0; i < 16; ++i)
                W[i] = load_be32(block + i * 4);
            for (int i = 16; i < 64; ++i)
                W[i] = sigma1_256(W[i - 2]) + W[i - 7] + sigma0_256(W[i - 15]) + W[i - 16];

            uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
            uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

            for (int i = 0; i < 64; ++i)
            {
                uint32_t T1 = h + Sigma1_256(e) + Ch32(e, f, g) + K256[i] + W[i];
                uint32_t T2 = Sigma0_256(a) + Maj32(a, b, c);
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

        // SHA-512 compression function: processes one 128-byte block
        void sha512_compress_portable(uint64_t state[8], const uint8_t block[128])
        {
            uint64_t W[80];
            for (int i = 0; i < 16; ++i)
                W[i] = load_be64(block + i * 8);
            for (int i = 16; i < 80; ++i)
                W[i] = sigma1_512(W[i - 2]) + W[i - 7] + sigma0_512(W[i - 15]) + W[i - 16];

            uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
            uint64_t e = state[4], f = state[5], g = state[6], h = state[7];

            for (int i = 0; i < 80; ++i)
            {
                uint64_t T1 = h + Sigma1_512(e) + Ch64(e, f, g) + K512[i] + W[i];
                uint64_t T2 = Sigma0_512(a) + Maj64(a, b, c);
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

    } // namespace internal
} // namespace tinysha
