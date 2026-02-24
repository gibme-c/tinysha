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

        // Keccak-f[1600] round constants
        static constexpr uint64_t RC[24] = {
            0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
            0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
            0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
            0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
            0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
            0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
        };

        // Rotation offsets for rho step
        static constexpr int ROTC[24] = {
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
        };

        // Pi step permutation indices
        static constexpr int PILN[24] = {
            10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
        };

        static inline uint64_t rotl64(uint64_t x, int n)
        {
            return (x << n) | (x >> (64 - n));
        }

        void keccak_f1600_portable(uint64_t state[25])
        {
            for (int round = 0; round < 24; ++round)
            {
                // Theta
                uint64_t C[5];
                for (int x = 0; x < 5; ++x)
                    C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];

                uint64_t D[5];
                for (int x = 0; x < 5; ++x)
                    D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);

                for (int x = 0; x < 5; ++x)
                    for (int y = 0; y < 25; y += 5)
                        state[y + x] ^= D[x];

                // Rho and Pi
                uint64_t t = state[1];
                for (int i = 0; i < 24; ++i)
                {
                    int j = PILN[i];
                    uint64_t tmp = state[j];
                    state[j] = rotl64(t, ROTC[i]);
                    t = tmp;
                }

                // Chi
                for (int y = 0; y < 25; y += 5)
                {
                    uint64_t t0 = state[y + 0];
                    uint64_t t1 = state[y + 1];
                    uint64_t t2 = state[y + 2];
                    uint64_t t3 = state[y + 3];
                    uint64_t t4 = state[y + 4];
                    state[y + 0] = t0 ^ (~t1 & t2);
                    state[y + 1] = t1 ^ (~t2 & t3);
                    state[y + 2] = t2 ^ (~t3 & t4);
                    state[y + 3] = t3 ^ (~t4 & t0);
                    state[y + 4] = t4 ^ (~t0 & t1);
                }

                // Iota
                state[0] ^= RC[round];
            }
        }

    } // namespace internal
} // namespace tinysha
