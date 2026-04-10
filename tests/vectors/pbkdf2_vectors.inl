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

// PBKDF2-HMAC-SHA-256 test vectors
// Derived from RFC 6070 (adapted from SHA-1 to SHA-256) and
// draft-josefsson-scrypt-kdf (which includes PBKDF2-SHA-256 vectors)
#pragma once

#include <cstddef>
#include <cstdint>

struct PBKDF2Vector
{
    const uint8_t *password;
    size_t password_len;
    const uint8_t *salt;
    size_t salt_len;
    uint32_t iterations;
    size_t dk_len;
    const uint8_t *expected;
    size_t expected_len;
};

// "passwd" / "salt" / 1 iteration / 64 bytes
// From draft-josefsson-scrypt-kdf section 11
static constexpr uint8_t pbkdf2_pw_1[] = {0x70, 0x61, 0x73, 0x73, 0x77, 0x64}; // "passwd"
static constexpr uint8_t pbkdf2_salt_1[] = {0x73, 0x61, 0x6c, 0x74}; // "salt"
static constexpr uint8_t pbkdf2_expected_1[] = {
    0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f, 0xec, 0x16, 0x91, 0xc2, 0x25, 0x44, 0xb6, 0x05,
    0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde, 0x04, 0x65, 0xe6, 0x8b, 0x9d, 0x57, 0xc2, 0x0d, 0xac, 0xbc,
    0x49, 0xca, 0x9c, 0xcc, 0xf1, 0x79, 0xb6, 0x45, 0x99, 0x16, 0x64, 0xb3, 0x9d, 0x77, 0xef, 0x31,
    0x7c, 0x71, 0xb8, 0x45, 0xb1, 0xe3, 0x0b, 0xd5, 0x09, 0x11, 0x20, 0x41, 0xd3, 0xa1, 0x97, 0x83,
};

// "Password" / "NaCl" / 80000 iterations / 64 bytes
// From draft-josefsson-scrypt-kdf section 11
static constexpr uint8_t pbkdf2_pw_2[] = {0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64}; // "Password"
static constexpr uint8_t pbkdf2_salt_2[] = {0x4e, 0x61, 0x43, 0x6c}; // "NaCl"
static constexpr uint8_t pbkdf2_expected_2[] = {
    0x4d, 0xdc, 0xd8, 0xf6, 0x0b, 0x98, 0xbe, 0x21, 0x83, 0x0c, 0xee, 0x5e, 0xf2, 0x27, 0x01, 0xf9,
    0x64, 0x1a, 0x44, 0x18, 0xd0, 0x4c, 0x04, 0x14, 0xae, 0xff, 0x08, 0x87, 0x6b, 0x34, 0xab, 0x56,
    0xa1, 0xd4, 0x25, 0xa1, 0x22, 0x58, 0x33, 0x54, 0x9a, 0xdb, 0x84, 0x1b, 0x51, 0xc9, 0xb3, 0x17,
    0x6a, 0x27, 0x2b, 0xde, 0xbb, 0xa1, 0xd0, 0x78, 0x47, 0x8f, 0x62, 0xb3, 0x97, 0xf3, 0x3c, 0x8d,
};

static constexpr PBKDF2Vector pbkdf2_vectors[] = {
    {pbkdf2_pw_1, 6, pbkdf2_salt_1, 4, 1, 64, pbkdf2_expected_1, 64},
    // Skipping the 80000-iteration vector by default (too slow for unit tests)
    // Uncomment for thorough testing:
    // { pbkdf2_pw_2, 8, pbkdf2_salt_2, 4, 80000, 64, pbkdf2_expected_2, 64 },
};

static constexpr size_t pbkdf2_vector_count = sizeof(pbkdf2_vectors) / sizeof(pbkdf2_vectors[0]);
