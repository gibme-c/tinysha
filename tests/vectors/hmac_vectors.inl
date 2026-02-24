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

// HMAC test vectors from RFC 4231
#pragma once

#include <cstdint>
#include <cstddef>

struct HMACVector {
    const uint8_t* key;
    size_t key_len;
    const uint8_t* data;
    size_t data_len;
    uint8_t expected_sha256[32];
};

// RFC 4231 Test Case 1
static constexpr uint8_t hmac_key_1[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b,
};
// "Hi There"
static constexpr uint8_t hmac_data_1[] = {
    0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65,
};

// RFC 4231 Test Case 2
// key = "Jefe"
static constexpr uint8_t hmac_key_2[] = {0x4a, 0x65, 0x66, 0x65};
// "what do ya want for nothing?"
static constexpr uint8_t hmac_data_2[] = {
    0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20,
    0x79, 0x61, 0x20, 0x77, 0x61, 0x6e, 0x74, 0x20,
    0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68,
    0x69, 0x6e, 0x67, 0x3f,
};

static constexpr HMACVector hmac_vectors[] = {
    // Test Case 1: HMAC-SHA-256
    { hmac_key_1, 20, hmac_data_1, 8,
      {0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
       0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
       0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
       0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7} },
    // Test Case 2: HMAC-SHA-256
    { hmac_key_2, 4, hmac_data_2, 28,
      {0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
       0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
       0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
       0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43} },
};

static constexpr size_t hmac_vector_count = sizeof(hmac_vectors) / sizeof(hmac_vectors[0]);
