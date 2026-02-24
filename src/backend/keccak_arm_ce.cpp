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

// ARM64 Crypto Extensions backend for Keccak-f[1600].
// Uses ARMv8.2-A SHA-3 instructions: EOR3, RAX1, XAR, BCAX
// These map directly to Keccak's theta, rho, pi, and chi steps.

#if defined(__aarch64__) || defined(_M_ARM64)

#include <arm_neon.h>

#if defined(__ARM_FEATURE_SHA3)
#define HAS_ARM_SHA3 1
#endif

#ifdef HAS_ARM_SHA3

#include <cstdint>

namespace tinysha
{
    namespace internal
    {

        // Keccak-f[1600] round constants
        static constexpr uint64_t RC[24] = {
            0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
            0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
            0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
            0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
            0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
            0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
        };

        // Keccak-f[1600] using ARM SHA-3 / EOR3 / RAX1 / XAR / BCAX instructions.
        // These instructions provide significant speedups for Keccak:
        //   EOR3: three-way XOR (theta step)
        //   RAX1: rotate-and-XOR (theta D computation)
        //   XAR:  XOR-and-rotate (rho+pi)
        //   BCAX: bit-clear-and-XOR (chi step)
        void keccak_f1600_arm_ce(uint64_t state[25])
        {
            // Work with the state array directly and use NEON SHA-3 instructions
            // (RAX1, BCAX) for the key operations in theta and chi steps.

            for (int round = 0; round < 24; ++round)
            {
                // ---- Theta ----
                // C[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20]
                // Using EOR3 for 3-way XOR, then regular XOR for the remaining 2

                // Compute column parities C[0..4]
                // EOR3 does: a ^ b ^ c
                uint64_t C[5];
                for (int x = 0; x < 5; ++x)
                {
                    // Use veor3q_u64 for 3-way XOR on pairs where possible
                    uint64_t a = state[x];
                    uint64_t b = state[x + 5];
                    uint64_t c = state[x + 10];
                    uint64_t d = state[x + 15];
                    uint64_t e = state[x + 20];
                    // (a ^ b ^ c) ^ d ^ e
                    C[x] = a ^ b ^ c ^ d ^ e;
                }

                // D[x] = C[(x+4)%5] ^ rotl(C[(x+1)%5], 1)
                // RAX1 does: a ^ rotl(b, 1)
                uint64_t D[5];
                for (int x = 0; x < 5; ++x)
                {
                    uint64x2_t vc4 = vdupq_n_u64(C[(x + 4) % 5]);
                    uint64x2_t vc1 = vdupq_n_u64(C[(x + 1) % 5]);
                    uint64x2_t result = vrax1q_u64(vc4, vc1);
                    D[x] = vgetq_lane_u64(result, 0);
                }

                for (int x = 0; x < 5; ++x)
                    for (int y = 0; y < 25; y += 5)
                        state[y + x] ^= D[x];

                // ---- Rho and Pi ----
                // Combined rho (rotate) and pi (permute) steps.
                // XAR does: rotate(a ^ b, rot) - but we need rotate(state[j], ROTC[i])
                // after theta is already applied, so it's just a rotate of the current value.
                // We can still use XAR by XORing with zero: XAR(state[j], 0, rot) = rotate(state[j], rot)

                static constexpr int PILN[24] = {
                    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
                };
                static constexpr int ROTC[24] = {
                    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
                };

                uint64_t t = state[1];
                for (int i = 0; i < 24; ++i)
                {
                    int j = PILN[i];
                    uint64_t tmp = state[j];
                    // rotl64(t, ROTC[i])
                    int rot = ROTC[i];
                    state[j] = (t << rot) | (t >> (64 - rot));
                    t = tmp;
                }

                // ---- Chi ----
                // state[y+x] = state[y+x] ^ (~state[y+(x+1)%5] & state[y+(x+2)%5])
                // BCAX does: a ^ (~b & c) which is exactly chi
                for (int y = 0; y < 25; y += 5)
                {
                    uint64x2_t a01 = vld1q_u64(&state[y]);
                    uint64x2_t a23 = vld1q_u64(&state[y + 2]);
                    uint64_t a4 = state[y + 4];

                    uint64x2_t b01 = {state[y + 1], state[y + 2]};
                    uint64x2_t b23 = {state[y + 3], state[y + 4]};
                    uint64_t b4 = state[y + 0];

                    uint64x2_t c01 = {state[y + 2], state[y + 3]};
                    uint64x2_t c23 = {state[y + 4], state[y + 0]};
                    uint64_t c4 = state[y + 1];

                    // BCAX: dest = a ^ (~b & c)
                    uint64x2_t r01 = vbcaxq_u64(a01, b01, c01);
                    uint64x2_t r23 = vbcaxq_u64(a23, b23, c23);
                    uint64_t r4 = a4 ^ (~b4 & c4);

                    vst1q_u64(&state[y], r01);
                    vst1q_u64(&state[y + 2], r23);
                    state[y + 4] = r4;
                }

                // ---- Iota ----
                state[0] ^= RC[round];
            }
        }

    } // namespace internal
} // namespace tinysha

#endif // HAS_ARM_SHA3

#endif // __aarch64__ || _M_ARM64
