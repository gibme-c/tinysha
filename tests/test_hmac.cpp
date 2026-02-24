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
#include "vectors/hmac_vectors.inl"

#include <tinysha.h>

TEST(hmac_sha256_rfc4231)
{
    for (size_t i = 0; i < hmac_vector_count; ++i)
    {
        const auto &v = hmac_vectors[i];
        std::vector<uint8_t> key(v.key, v.key + v.key_len);
        std::vector<uint8_t> data(v.data, v.data + v.data_len);
        auto mac = tinysha::hmac<tinysha::SHA256Traits>(key, data);
        std::vector<uint8_t> expected(v.expected_sha256, v.expected_sha256 + 32);
        ASSERT_EQ(mac, expected);
    }
}

TEST(hmac_sha256_c_api)
{
    const auto &v = hmac_vectors[0];
    uint8_t out[32];
    int rc = tinysha_hmac_sha256(v.key, v.key_len, v.data, v.data_len, out, 32);
    ASSERT_TRUE(rc == 0);
    std::vector<uint8_t> result(out, out + 32);
    std::vector<uint8_t> expected(v.expected_sha256, v.expected_sha256 + 32);
    ASSERT_EQ(result, expected);
}