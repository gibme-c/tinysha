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

#include "test_harness.h"
#include "vectors/sha3_512_vectors.inl"

#include <tinysha.h>

TEST(sha3_512_nist_vectors)
{
    for (size_t i = 0; i < sha3_512_vector_count; ++i)
    {
        const auto &v = sha3_512_vectors[i];
        std::vector<uint8_t> input(v.input, v.input + v.input_len);
        auto digest = tinysha::sha3_512(input);
        std::vector<uint8_t> expected(v.expected, v.expected + 64);
        ASSERT_EQ(digest, expected);
    }
}

TEST(sha3_512_c_api)
{
    uint8_t out[64];
    const uint8_t abc[] = {0x61, 0x62, 0x63};
    int rc = tinysha_sha3_512(abc, 3, out, 64);
    ASSERT_TRUE(rc == 0);
    std::vector<uint8_t> result(out, out + 64);
    std::vector<uint8_t> expected(sha3_512_vectors[1].expected, sha3_512_vectors[1].expected + 64);
    ASSERT_EQ(result, expected);
}