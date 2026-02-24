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
// All 25 state lanes live in NEON registers across all 24 rounds.
// Theta: 10x EOR3 + 5x RAX1
// Rho+Pi merged with Theta: 1x EOR (lane 0) + 24x XAR
// Chi: 25x BCAX (5 rows x 5 lanes)
// Iota: 1x EOR

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

        // Keccak-f[1600] using ARM SHA-3 instructions with 25-register layout.
        // All 25 state lanes are held in uint64x2_t registers (duplicated in both
        // halves) for the entire 24-round computation. This eliminates all memory
        // traffic between rounds.
        void keccak_f1600_arm_ce(uint64_t state[25])
        {
            // Load all 25 lanes into NEON registers
            uint64x2_t v0 = vdupq_n_u64(state[0]);
            uint64x2_t v1 = vdupq_n_u64(state[1]);
            uint64x2_t v2 = vdupq_n_u64(state[2]);
            uint64x2_t v3 = vdupq_n_u64(state[3]);
            uint64x2_t v4 = vdupq_n_u64(state[4]);
            uint64x2_t v5 = vdupq_n_u64(state[5]);
            uint64x2_t v6 = vdupq_n_u64(state[6]);
            uint64x2_t v7 = vdupq_n_u64(state[7]);
            uint64x2_t v8 = vdupq_n_u64(state[8]);
            uint64x2_t v9 = vdupq_n_u64(state[9]);
            uint64x2_t v10 = vdupq_n_u64(state[10]);
            uint64x2_t v11 = vdupq_n_u64(state[11]);
            uint64x2_t v12 = vdupq_n_u64(state[12]);
            uint64x2_t v13 = vdupq_n_u64(state[13]);
            uint64x2_t v14 = vdupq_n_u64(state[14]);
            uint64x2_t v15 = vdupq_n_u64(state[15]);
            uint64x2_t v16 = vdupq_n_u64(state[16]);
            uint64x2_t v17 = vdupq_n_u64(state[17]);
            uint64x2_t v18 = vdupq_n_u64(state[18]);
            uint64x2_t v19 = vdupq_n_u64(state[19]);
            uint64x2_t v20 = vdupq_n_u64(state[20]);
            uint64x2_t v21 = vdupq_n_u64(state[21]);
            uint64x2_t v22 = vdupq_n_u64(state[22]);
            uint64x2_t v23 = vdupq_n_u64(state[23]);
            uint64x2_t v24 = vdupq_n_u64(state[24]);

            for (int round = 0; round < 24; ++round)
            {
                // ---- Theta ----
                // Column parity: C[x] = st[x] ^ st[x+5] ^ st[x+10] ^ st[x+15] ^ st[x+20]
                // Two veor3 per column (10 instructions total)
                uint64x2_t c0 = veor3q_u64(v0, v5, v10);
                c0 = veor3q_u64(c0, v15, v20);
                uint64x2_t c1 = veor3q_u64(v1, v6, v11);
                c1 = veor3q_u64(c1, v16, v21);
                uint64x2_t c2 = veor3q_u64(v2, v7, v12);
                c2 = veor3q_u64(c2, v17, v22);
                uint64x2_t c3 = veor3q_u64(v3, v8, v13);
                c3 = veor3q_u64(c3, v18, v23);
                uint64x2_t c4 = veor3q_u64(v4, v9, v14);
                c4 = veor3q_u64(c4, v19, v24);

                // D[x] = C[(x+4)%5] ^ rotl(C[(x+1)%5], 1)
                // vrax1q_u64(a, b) = a ^ rotl(b, 1) — 5 instructions
                uint64x2_t d0 = vrax1q_u64(c4, c1);
                uint64x2_t d1 = vrax1q_u64(c0, c2);
                uint64x2_t d2 = vrax1q_u64(c1, c3);
                uint64x2_t d3 = vrax1q_u64(c2, c4);
                uint64x2_t d4 = vrax1q_u64(c3, c0);

                // ---- Theta (lane 0) + Rho + Pi merged ----
                // Lane 0: rho offset = 0, just apply theta
                v0 = veorq_u64(v0, d0);

                // Pi chain: vxarq_u64(src, d_val, 64-rho) = ROTR(src ^ d_val, 64-rho)
                //   = ROTL(src ^ d_val, rho)
                // This merges theta XOR + rho rotation into one instruction per lane.
                // The pi permutation is implicit in the source/destination ordering.
                //
                // Chain: 1->10->7->11->17->18->3->5->16->8->21->24->4->15->23->
                //        19->13->12->2->20->14->22->9->6->1

                uint64x2_t t, s;

                // Step 0: src=1 (D[1]), dst=10, rho=1, imm=63
                t = vxarq_u64(v1, d1, 63);
                s = v10;
                v10 = t;

                // Step 1: src=10 (D[0]), dst=7, rho=3, imm=61
                t = vxarq_u64(s, d0, 61);
                s = v7;
                v7 = t;

                // Step 2: src=7 (D[2]), dst=11, rho=6, imm=58
                t = vxarq_u64(s, d2, 58);
                s = v11;
                v11 = t;

                // Step 3: src=11 (D[1]), dst=17, rho=10, imm=54
                t = vxarq_u64(s, d1, 54);
                s = v17;
                v17 = t;

                // Step 4: src=17 (D[2]), dst=18, rho=15, imm=49
                t = vxarq_u64(s, d2, 49);
                s = v18;
                v18 = t;

                // Step 5: src=18 (D[3]), dst=3, rho=21, imm=43
                t = vxarq_u64(s, d3, 43);
                s = v3;
                v3 = t;

                // Step 6: src=3 (D[3]), dst=5, rho=28, imm=36
                t = vxarq_u64(s, d3, 36);
                s = v5;
                v5 = t;

                // Step 7: src=5 (D[0]), dst=16, rho=36, imm=28
                t = vxarq_u64(s, d0, 28);
                s = v16;
                v16 = t;

                // Step 8: src=16 (D[1]), dst=8, rho=45, imm=19
                t = vxarq_u64(s, d1, 19);
                s = v8;
                v8 = t;

                // Step 9: src=8 (D[3]), dst=21, rho=55, imm=9
                t = vxarq_u64(s, d3, 9);
                s = v21;
                v21 = t;

                // Step 10: src=21 (D[1]), dst=24, rho=2, imm=62
                t = vxarq_u64(s, d1, 62);
                s = v24;
                v24 = t;

                // Step 11: src=24 (D[4]), dst=4, rho=14, imm=50
                t = vxarq_u64(s, d4, 50);
                s = v4;
                v4 = t;

                // Step 12: src=4 (D[4]), dst=15, rho=27, imm=37
                t = vxarq_u64(s, d4, 37);
                s = v15;
                v15 = t;

                // Step 13: src=15 (D[0]), dst=23, rho=41, imm=23
                t = vxarq_u64(s, d0, 23);
                s = v23;
                v23 = t;

                // Step 14: src=23 (D[3]), dst=19, rho=56, imm=8
                t = vxarq_u64(s, d3, 8);
                s = v19;
                v19 = t;

                // Step 15: src=19 (D[4]), dst=13, rho=8, imm=56
                t = vxarq_u64(s, d4, 56);
                s = v13;
                v13 = t;

                // Step 16: src=13 (D[3]), dst=12, rho=25, imm=39
                t = vxarq_u64(s, d3, 39);
                s = v12;
                v12 = t;

                // Step 17: src=12 (D[2]), dst=2, rho=43, imm=21
                t = vxarq_u64(s, d2, 21);
                s = v2;
                v2 = t;

                // Step 18: src=2 (D[2]), dst=20, rho=62, imm=2
                t = vxarq_u64(s, d2, 2);
                s = v20;
                v20 = t;

                // Step 19: src=20 (D[0]), dst=14, rho=18, imm=46
                t = vxarq_u64(s, d0, 46);
                s = v14;
                v14 = t;

                // Step 20: src=14 (D[4]), dst=22, rho=39, imm=25
                t = vxarq_u64(s, d4, 25);
                s = v22;
                v22 = t;

                // Step 21: src=22 (D[2]), dst=9, rho=61, imm=3
                t = vxarq_u64(s, d2, 3);
                s = v9;
                v9 = t;

                // Step 22: src=9 (D[4]), dst=6, rho=20, imm=44
                t = vxarq_u64(s, d4, 44);
                s = v6;
                v6 = t;

                // Step 23: src=6 (D[1]), dst=1, rho=44, imm=20
                v1 = vxarq_u64(s, d1, 20);

                // ---- Chi ----
                // vbcaxq_u64(a, c, b) = a ^ (c & ~b) = a ^ (~b & c)
                // Row 0
                {
                    uint64x2_t t0 = v0, t1 = v1, t2 = v2, t3 = v3, t4 = v4;
                    v0 = vbcaxq_u64(t0, t2, t1);
                    v1 = vbcaxq_u64(t1, t3, t2);
                    v2 = vbcaxq_u64(t2, t4, t3);
                    v3 = vbcaxq_u64(t3, t0, t4);
                    v4 = vbcaxq_u64(t4, t1, t0);
                }
                // Row 1
                {
                    uint64x2_t t0 = v5, t1 = v6, t2 = v7, t3 = v8, t4 = v9;
                    v5 = vbcaxq_u64(t0, t2, t1);
                    v6 = vbcaxq_u64(t1, t3, t2);
                    v7 = vbcaxq_u64(t2, t4, t3);
                    v8 = vbcaxq_u64(t3, t0, t4);
                    v9 = vbcaxq_u64(t4, t1, t0);
                }
                // Row 2
                {
                    uint64x2_t t0 = v10, t1 = v11, t2 = v12, t3 = v13, t4 = v14;
                    v10 = vbcaxq_u64(t0, t2, t1);
                    v11 = vbcaxq_u64(t1, t3, t2);
                    v12 = vbcaxq_u64(t2, t4, t3);
                    v13 = vbcaxq_u64(t3, t0, t4);
                    v14 = vbcaxq_u64(t4, t1, t0);
                }
                // Row 3
                {
                    uint64x2_t t0 = v15, t1 = v16, t2 = v17, t3 = v18, t4 = v19;
                    v15 = vbcaxq_u64(t0, t2, t1);
                    v16 = vbcaxq_u64(t1, t3, t2);
                    v17 = vbcaxq_u64(t2, t4, t3);
                    v18 = vbcaxq_u64(t3, t0, t4);
                    v19 = vbcaxq_u64(t4, t1, t0);
                }
                // Row 4
                {
                    uint64x2_t t0 = v20, t1 = v21, t2 = v22, t3 = v23, t4 = v24;
                    v20 = vbcaxq_u64(t0, t2, t1);
                    v21 = vbcaxq_u64(t1, t3, t2);
                    v22 = vbcaxq_u64(t2, t4, t3);
                    v23 = vbcaxq_u64(t3, t0, t4);
                    v24 = vbcaxq_u64(t4, t1, t0);
                }

                // ---- Iota ----
                v0 = veorq_u64(v0, vdupq_n_u64(RC[round]));
            }

            // Store all 25 lanes back
            state[0] = vgetq_lane_u64(v0, 0);
            state[1] = vgetq_lane_u64(v1, 0);
            state[2] = vgetq_lane_u64(v2, 0);
            state[3] = vgetq_lane_u64(v3, 0);
            state[4] = vgetq_lane_u64(v4, 0);
            state[5] = vgetq_lane_u64(v5, 0);
            state[6] = vgetq_lane_u64(v6, 0);
            state[7] = vgetq_lane_u64(v7, 0);
            state[8] = vgetq_lane_u64(v8, 0);
            state[9] = vgetq_lane_u64(v9, 0);
            state[10] = vgetq_lane_u64(v10, 0);
            state[11] = vgetq_lane_u64(v11, 0);
            state[12] = vgetq_lane_u64(v12, 0);
            state[13] = vgetq_lane_u64(v13, 0);
            state[14] = vgetq_lane_u64(v14, 0);
            state[15] = vgetq_lane_u64(v15, 0);
            state[16] = vgetq_lane_u64(v16, 0);
            state[17] = vgetq_lane_u64(v17, 0);
            state[18] = vgetq_lane_u64(v18, 0);
            state[19] = vgetq_lane_u64(v19, 0);
            state[20] = vgetq_lane_u64(v20, 0);
            state[21] = vgetq_lane_u64(v21, 0);
            state[22] = vgetq_lane_u64(v22, 0);
            state[23] = vgetq_lane_u64(v23, 0);
            state[24] = vgetq_lane_u64(v24, 0);
        }

    } // namespace internal
} // namespace tinysha

#endif // HAS_ARM_SHA3

#endif // __aarch64__ || _M_ARM64
