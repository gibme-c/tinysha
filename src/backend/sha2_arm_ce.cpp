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

// ARM64 Crypto Extensions backend for SHA-256 and SHA-512.
// SHA-256 CE: ARMv8.0-A + crypto (vsha256h, vsha256h2, vsha256su0, vsha256su1)
// SHA-512 CE: ARMv8.2-A + sha512 (vsha512h, vsha512h2, vsha512su0, vsha512su1)

#if defined(__aarch64__) || defined(_M_ARM64)

#include <arm_neon.h>

// GCC/Clang: rely on feature-test macros set by -march flags.
// MSVC ARM64: SHA-256 CE intrinsics are always available; runtime CPUID
// gates actual usage in the dispatch (sha256.cpp).
#if defined(__ARM_FEATURE_CRYPTO) || defined(__ARM_FEATURE_SHA2) || (defined(_MSC_VER) && defined(_M_ARM64))
#define HAS_ARM_SHA256 1
#endif

#if defined(__ARM_FEATURE_SHA512)
#define HAS_ARM_SHA512 1
#endif

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

#ifdef HAS_ARM_SHA256

        // SHA-256 compress using ARM Crypto Extensions.
        // The hardware SHA-256 instructions operate on NEON 128-bit vectors.
        // State layout in NEON: ABCD = {A,B,C,D}, EFGH = {E,F,G,H}
        // The vsha256hq_u32 instruction processes 4 rounds at a time.
        void sha256_compress_arm_ce(uint32_t state[8], const uint8_t block[64])
        {
            // Load state into NEON vectors
            // ARM SHA-256 intrinsics expect ABCD and EFGH in separate vectors
            uint32x4_t ABCD = vld1q_u32(&state[0]);
            uint32x4_t EFGH = vld1q_u32(&state[4]);

            // Save original state for final addition
            uint32x4_t ABCD_save = ABCD;
            uint32x4_t EFGH_save = EFGH;

            // Load message block as big-endian 32-bit words
            uint32x4_t W0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 0)));
            uint32x4_t W1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 16)));
            uint32x4_t W2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 32)));
            uint32x4_t W3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 48)));

            uint32x4_t TMP;

            // Rounds 0-3
            TMP = vaddq_u32(W0, vld1q_u32(&K256[0]));
            uint32x4_t ABCD_prev = ABCD;
            ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
            EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);

            // Rounds 4-7
            TMP = vaddq_u32(W1, vld1q_u32(&K256[4]));
            ABCD_prev = ABCD;
            ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
            EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
            W0 = vsha256su1q_u32(vsha256su0q_u32(W0, W1), W2, W3);

            // Rounds 8-11
            TMP = vaddq_u32(W2, vld1q_u32(&K256[8]));
            ABCD_prev = ABCD;
            ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
            EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
            W1 = vsha256su1q_u32(vsha256su0q_u32(W1, W2), W3, W0);

            // Rounds 12-15
            TMP = vaddq_u32(W3, vld1q_u32(&K256[12]));
            ABCD_prev = ABCD;
            ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
            EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
            W2 = vsha256su1q_u32(vsha256su0q_u32(W2, W3), W0, W1);

            // Rounds 16-19
            TMP = vaddq_u32(W0, vld1q_u32(&K256[16]));
            ABCD_prev = ABCD;
            ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
            EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
            W3 = vsha256su1q_u32(vsha256su0q_u32(W3, W0), W1, W2);

            // Rounds 20-23
            TMP = vaddq_u32(W1, vld1q_u32(&K256[20]));
            ABCD_prev = ABCD;
            ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
            EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
            W0 = vsha256su1q_u32(vsha256su0q_u32(W0, W1), W2, W3);

            // Rounds 24-27
            TMP = vaddq_u32(W2, vld1q_u32(&K256[24]));
            ABCD_prev = ABCD;
            ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
            EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
            W1 = vsha256su1q_u32(vsha256su0q_u32(W1, W2), W3, W0);

            // Rounds 28-31
            TMP = vaddq_u32(W3, vld1q_u32(&K256[28]));
            ABCD_prev = ABCD;
            ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
            EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
            W2 = vsha256su1q_u32(vsha256su0q_u32(W2, W3), W0, W1);

            // Rounds 32-35
            TMP = vaddq_u32(W0, vld1q_u32(&K256[32]));
            ABCD_prev = ABCD;
            ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
            EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
            W3 = vsha256su1q_u32(vsha256su0q_u32(W3, W0), W1, W2);

            // Rounds 36-39
            TMP = vaddq_u32(W1, vld1q_u32(&K256[36]));
            ABCD_prev = ABCD;
            ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
            EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
            W0 = vsha256su1q_u32(vsha256su0q_u32(W0, W1), W2, W3);

            // Rounds 40-43
            TMP = vaddq_u32(W2, vld1q_u32(&K256[40]));
            ABCD_prev = ABCD;
            ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
            EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
            W1 = vsha256su1q_u32(vsha256su0q_u32(W1, W2), W3, W0);

            // Rounds 44-47
            TMP = vaddq_u32(W3, vld1q_u32(&K256[44]));
            ABCD_prev = ABCD;
            ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
            EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
            W2 = vsha256su1q_u32(vsha256su0q_u32(W2, W3), W0, W1);

            // Rounds 48-51
            TMP = vaddq_u32(W0, vld1q_u32(&K256[48]));
            ABCD_prev = ABCD;
            ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
            EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);
            W3 = vsha256su1q_u32(vsha256su0q_u32(W3, W0), W1, W2);

            // Rounds 52-55
            TMP = vaddq_u32(W1, vld1q_u32(&K256[52]));
            ABCD_prev = ABCD;
            ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
            EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);

            // Rounds 56-59
            TMP = vaddq_u32(W2, vld1q_u32(&K256[56]));
            ABCD_prev = ABCD;
            ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
            EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);

            // Rounds 60-63
            TMP = vaddq_u32(W3, vld1q_u32(&K256[60]));
            ABCD_prev = ABCD;
            ABCD = vsha256hq_u32(ABCD, EFGH, TMP);
            EFGH = vsha256h2q_u32(EFGH, ABCD_prev, TMP);

            // Add saved state
            ABCD = vaddq_u32(ABCD, ABCD_save);
            EFGH = vaddq_u32(EFGH, EFGH_save);

            // Store state back
            vst1q_u32(&state[0], ABCD);
            vst1q_u32(&state[4], EFGH);
        }

#endif // HAS_ARM_SHA256

#ifdef HAS_ARM_SHA512

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

        // SHA-512 compress using ARMv8.2-A SHA-512 Crypto Extensions.
        // Follows the canonical Linux kernel / OpenSSL pattern:
        //   1. Pre-add W+K into the GH register
        //   2. sha512h computes intermediate using modified GH
        //   3. sha512h2 computes new AB from intermediate
        //   4. Rotate register aliases: GH→EF→CD→AB shifts right by one pair
        void sha512_compress_arm_ce(uint64_t state[8], const uint8_t block[128])
        {
            // Load state: AB, CD, EF, GH as pairs of uint64
            uint64x2_t AB = vld1q_u64(&state[0]);
            uint64x2_t CD = vld1q_u64(&state[2]);
            uint64x2_t EF = vld1q_u64(&state[4]);
            uint64x2_t GH = vld1q_u64(&state[6]);

            uint64x2_t AB_save = AB;
            uint64x2_t CD_save = CD;
            uint64x2_t EF_save = EF;
            uint64x2_t GH_save = GH;

            // Load 16 message words as big-endian
            uint64x2_t W[8];
            W[0] = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 0)));
            W[1] = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 16)));
            W[2] = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 32)));
            W[3] = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 48)));
            W[4] = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 64)));
            W[5] = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 80)));
            W[6] = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 96)));
            W[7] = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 112)));

            // Process 80 rounds in groups of 2, rotating register aliases.
            // The sha512h instruction expects GH to already contain (GH + W + K).
            // After sha512h + sha512h2, the result (new AB) lands in what was GH,
            // then we rotate: old AB→CD, old CD→EF, old EF→GH.

// Two rounds: compute new AB into 'gh', then rotate register aliases.
// Following the canonical Linux kernel / BouncyCastle pattern:
//   1. Swap W+K halves (align h-word with high lane where h lives in gh)
//   2. Add swapped W+K into gh to form the initial sum for sha512h
//   3. Extract cross-lane state pairs fg, de from ORIGINAL state
//   4. sha512h produces intermediate; sha512h2 produces new AB
//   5. cd += intermed to propagate the Sigma1+Ch contribution (new EF after rotation)
#define SHA512_2ROUNDS(ab, cd, ef, gh, wi, ki)                         \
    do                                                                  \
    {                                                                   \
        uint64x2_t wk = vaddq_u64(W[wi], vld1q_u64(&K512[ki]));        \
        wk = vextq_u64(wk, wk, 1);                                     \
        uint64x2_t fg = vextq_u64(ef, gh, 1);                          \
        uint64x2_t de = vextq_u64(cd, ef, 1);                          \
        uint64x2_t sum = vaddq_u64(wk, gh);                            \
        uint64x2_t intermed = vsha512hq_u64(sum, fg, de);              \
        gh = vsha512h2q_u64(intermed, cd, ab);                         \
        cd = vaddq_u64(cd, intermed);                                  \
    } while (0)

// Two rounds + message schedule update
#define SHA512_2ROUNDS_SCHED(ab, cd, ef, gh, wi, ki)             \
    do                                                           \
    {                                                            \
        SHA512_2ROUNDS(ab, cd, ef, gh, wi, ki);                  \
        W[wi] = vsha512su1q_u64(                                 \
            vsha512su0q_u64(W[wi], W[((wi) + 1) % 8]),           \
            W[((wi) + 7) % 8],                                   \
            vextq_u64(W[((wi) + 4) % 8], W[((wi) + 5) % 8], 1)); \
    } while (0)

            // Rounds 0-63: with message schedule
            // Register rotation is done by swapping which variable is ab/cd/ef/gh.
            // After each round pair, what was 'gh' now holds new AB.
            // Round pair 0-1:   ab=AB cd=CD ef=EF gh=GH, result in GH
            SHA512_2ROUNDS_SCHED(AB, CD, EF, GH, 0, 0);
            // Round pair 2-3:   ab=GH cd=AB ef=CD gh=EF
            SHA512_2ROUNDS_SCHED(GH, AB, CD, EF, 1, 2);
            // Round pair 4-5:   ab=EF cd=GH ef=AB gh=CD
            SHA512_2ROUNDS_SCHED(EF, GH, AB, CD, 2, 4);
            // Round pair 6-7:   ab=CD cd=EF ef=GH gh=AB
            SHA512_2ROUNDS_SCHED(CD, EF, GH, AB, 3, 6);
            // Round pair 8-9:   back to ab=AB cd=CD ef=EF gh=GH
            SHA512_2ROUNDS_SCHED(AB, CD, EF, GH, 4, 8);
            SHA512_2ROUNDS_SCHED(GH, AB, CD, EF, 5, 10);
            SHA512_2ROUNDS_SCHED(EF, GH, AB, CD, 6, 12);
            SHA512_2ROUNDS_SCHED(CD, EF, GH, AB, 7, 14);

            SHA512_2ROUNDS_SCHED(AB, CD, EF, GH, 0, 16);
            SHA512_2ROUNDS_SCHED(GH, AB, CD, EF, 1, 18);
            SHA512_2ROUNDS_SCHED(EF, GH, AB, CD, 2, 20);
            SHA512_2ROUNDS_SCHED(CD, EF, GH, AB, 3, 22);
            SHA512_2ROUNDS_SCHED(AB, CD, EF, GH, 4, 24);
            SHA512_2ROUNDS_SCHED(GH, AB, CD, EF, 5, 26);
            SHA512_2ROUNDS_SCHED(EF, GH, AB, CD, 6, 28);
            SHA512_2ROUNDS_SCHED(CD, EF, GH, AB, 7, 30);

            SHA512_2ROUNDS_SCHED(AB, CD, EF, GH, 0, 32);
            SHA512_2ROUNDS_SCHED(GH, AB, CD, EF, 1, 34);
            SHA512_2ROUNDS_SCHED(EF, GH, AB, CD, 2, 36);
            SHA512_2ROUNDS_SCHED(CD, EF, GH, AB, 3, 38);
            SHA512_2ROUNDS_SCHED(AB, CD, EF, GH, 4, 40);
            SHA512_2ROUNDS_SCHED(GH, AB, CD, EF, 5, 42);
            SHA512_2ROUNDS_SCHED(EF, GH, AB, CD, 6, 44);
            SHA512_2ROUNDS_SCHED(CD, EF, GH, AB, 7, 46);

            SHA512_2ROUNDS_SCHED(AB, CD, EF, GH, 0, 48);
            SHA512_2ROUNDS_SCHED(GH, AB, CD, EF, 1, 50);
            SHA512_2ROUNDS_SCHED(EF, GH, AB, CD, 2, 52);
            SHA512_2ROUNDS_SCHED(CD, EF, GH, AB, 3, 54);
            SHA512_2ROUNDS_SCHED(AB, CD, EF, GH, 4, 56);
            SHA512_2ROUNDS_SCHED(GH, AB, CD, EF, 5, 58);
            SHA512_2ROUNDS_SCHED(EF, GH, AB, CD, 6, 60);
            SHA512_2ROUNDS_SCHED(CD, EF, GH, AB, 7, 62);

            // Rounds 64-79: no message schedule update needed
            SHA512_2ROUNDS(AB, CD, EF, GH, 0, 64);
            SHA512_2ROUNDS(GH, AB, CD, EF, 1, 66);
            SHA512_2ROUNDS(EF, GH, AB, CD, 2, 68);
            SHA512_2ROUNDS(CD, EF, GH, AB, 3, 70);
            SHA512_2ROUNDS(AB, CD, EF, GH, 4, 72);
            SHA512_2ROUNDS(GH, AB, CD, EF, 5, 74);
            SHA512_2ROUNDS(EF, GH, AB, CD, 6, 76);
            SHA512_2ROUNDS(CD, EF, GH, AB, 7, 78);

#undef SHA512_2ROUNDS
#undef SHA512_2ROUNDS_SCHED

            // After 40 round pairs (80 rounds), the register rotation has cycled
            // back to the original mapping: AB=AB, CD=CD, EF=EF, GH=GH
            AB = vaddq_u64(AB, AB_save);
            CD = vaddq_u64(CD, CD_save);
            EF = vaddq_u64(EF, EF_save);
            GH = vaddq_u64(GH, GH_save);

            vst1q_u64(&state[0], AB);
            vst1q_u64(&state[2], CD);
            vst1q_u64(&state[4], EF);
            vst1q_u64(&state[6], GH);
        }

#endif // HAS_ARM_SHA512

    } // namespace internal
} // namespace tinysha

#endif // __aarch64__ || _M_ARM64
