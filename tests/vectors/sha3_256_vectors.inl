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

// SHA3-256 test vectors from NIST
#pragma once

#include <cstdint>
#include <cstddef>

struct SHA3_256Vector {
    const uint8_t* input;
    size_t input_len;
    uint8_t expected[32];
};

static constexpr uint8_t sha3_256_in_0[] = {0};
static constexpr uint8_t sha3_256_in_1[] = {0x61, 0x62, 0x63};
// "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
static constexpr uint8_t sha3_256_in_2[] = {
    0x61, 0x62, 0x63, 0x64, 0x62, 0x63, 0x64, 0x65,
    0x63, 0x64, 0x65, 0x66, 0x64, 0x65, 0x66, 0x67,
    0x65, 0x66, 0x67, 0x68, 0x66, 0x67, 0x68, 0x69,
    0x67, 0x68, 0x69, 0x6a, 0x68, 0x69, 0x6a, 0x6b,
    0x69, 0x6a, 0x6b, 0x6c, 0x6a, 0x6b, 0x6c, 0x6d,
    0x6b, 0x6c, 0x6d, 0x6e, 0x6c, 0x6d, 0x6e, 0x6f,
    0x6d, 0x6e, 0x6f, 0x70, 0x6e, 0x6f, 0x70, 0x71,
};

static constexpr SHA3_256Vector sha3_256_vectors[] = {
    // Empty string
    { sha3_256_in_0, 0,
      {0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
       0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
       0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
       0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a} },
    // "abc"
    { sha3_256_in_1, 3,
      {0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
       0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
       0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
       0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32} },
    // 56-byte message
    { sha3_256_in_2, 56,
      {0x41, 0xc0, 0xdb, 0xa2, 0xa9, 0xd6, 0x24, 0x08,
       0x49, 0x10, 0x03, 0x76, 0xa8, 0x23, 0x5e, 0x2c,
       0x82, 0xe1, 0xb9, 0x99, 0x8a, 0x99, 0x9e, 0x21,
       0xdb, 0x32, 0xdd, 0x97, 0x49, 0x6d, 0x33, 0x76} },
};

static constexpr size_t sha3_256_vector_count = sizeof(sha3_256_vectors) / sizeof(sha3_256_vectors[0]);
