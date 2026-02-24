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

// Keccak x64 baseline backend — optimized with explicit register usage
// Same algorithm as portable but with unrolled inner loops for better
// instruction scheduling on out-of-order x86-64 cores.

#if defined(__x86_64__) || defined(_M_X64)

#include <cstdint>

namespace tinysha
{
    namespace internal
    {

        static constexpr uint64_t RC_x64[24] = {
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

        void keccak_f1600_x64(uint64_t st[25])
        {
            for (int round = 0; round < 24; ++round)
            {
                // Theta — compute column parities
                uint64_t bc0 = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
                uint64_t bc1 = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
                uint64_t bc2 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
                uint64_t bc3 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
                uint64_t bc4 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

                uint64_t d0 = bc4 ^ rotl64(bc1, 1);
                uint64_t d1 = bc0 ^ rotl64(bc2, 1);
                uint64_t d2 = bc1 ^ rotl64(bc3, 1);
                uint64_t d3 = bc2 ^ rotl64(bc4, 1);
                uint64_t d4 = bc3 ^ rotl64(bc0, 1);

                st[0] ^= d0;
                st[5] ^= d0;
                st[10] ^= d0;
                st[15] ^= d0;
                st[20] ^= d0;
                st[1] ^= d1;
                st[6] ^= d1;
                st[11] ^= d1;
                st[16] ^= d1;
                st[21] ^= d1;
                st[2] ^= d2;
                st[7] ^= d2;
                st[12] ^= d2;
                st[17] ^= d2;
                st[22] ^= d2;
                st[3] ^= d3;
                st[8] ^= d3;
                st[13] ^= d3;
                st[18] ^= d3;
                st[23] ^= d3;
                st[4] ^= d4;
                st[9] ^= d4;
                st[14] ^= d4;
                st[19] ^= d4;
                st[24] ^= d4;

                // Rho + Pi (fully unrolled)
                uint64_t t = st[1];
                uint64_t tmp;
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
                /* tmp = st[1]; */ st[1] = rotl64(t, 44);

                // Chi — unrolled by row
                for (int y = 0; y < 25; y += 5)
                {
                    uint64_t t0 = st[y + 0], t1 = st[y + 1], t2 = st[y + 2], t3 = st[y + 3], t4 = st[y + 4];
                    st[y + 0] = t0 ^ (~t1 & t2);
                    st[y + 1] = t1 ^ (~t2 & t3);
                    st[y + 2] = t2 ^ (~t3 & t4);
                    st[y + 3] = t3 ^ (~t4 & t0);
                    st[y + 4] = t4 ^ (~t0 & t1);
                }

                // Iota
                st[0] ^= RC_x64[round];
            }
        }

    } // namespace internal
} // namespace tinysha

#endif // x86_64
