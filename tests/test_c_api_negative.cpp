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

#include <tinysha.h>

// ── Hash C API negative tests ──────────────────────────────────────────────

TEST(hash_c_api_null_out)
{
    const uint8_t abc[] = {0x61, 0x62, 0x63};
    ASSERT_TRUE(tinysha_sha256(abc, 3, nullptr, 32) == -1);
    ASSERT_TRUE(tinysha_sha384(abc, 3, nullptr, 48) == -1);
    ASSERT_TRUE(tinysha_sha512(abc, 3, nullptr, 64) == -1);
    ASSERT_TRUE(tinysha_sha3_256(abc, 3, nullptr, 32) == -1);
    ASSERT_TRUE(tinysha_sha3_384(abc, 3, nullptr, 48) == -1);
    ASSERT_TRUE(tinysha_sha3_512(abc, 3, nullptr, 64) == -1);
}

TEST(hash_c_api_zero_out_len)
{
    const uint8_t abc[] = {0x61, 0x62, 0x63};
    uint8_t out[64];
    ASSERT_TRUE(tinysha_sha256(abc, 3, out, 0) == -1);
    ASSERT_TRUE(tinysha_sha384(abc, 3, out, 0) == -1);
    ASSERT_TRUE(tinysha_sha512(abc, 3, out, 0) == -1);
    ASSERT_TRUE(tinysha_sha3_256(abc, 3, out, 0) == -1);
    ASSERT_TRUE(tinysha_sha3_384(abc, 3, out, 0) == -1);
    ASSERT_TRUE(tinysha_sha3_512(abc, 3, out, 0) == -1);
}

TEST(hash_c_api_out_len_too_large)
{
    const uint8_t abc[] = {0x61, 0x62, 0x63};
    uint8_t out[128];
    ASSERT_TRUE(tinysha_sha256(abc, 3, out, 33) == -1);
    ASSERT_TRUE(tinysha_sha384(abc, 3, out, 49) == -1);
    ASSERT_TRUE(tinysha_sha512(abc, 3, out, 65) == -1);
    ASSERT_TRUE(tinysha_sha3_256(abc, 3, out, 33) == -1);
    ASSERT_TRUE(tinysha_sha3_384(abc, 3, out, 49) == -1);
    ASSERT_TRUE(tinysha_sha3_512(abc, 3, out, 65) == -1);
}

TEST(hash_c_api_null_data_nonzero_len)
{
    uint8_t out[64];
    ASSERT_TRUE(tinysha_sha256(nullptr, 1, out, 32) == -1);
    ASSERT_TRUE(tinysha_sha384(nullptr, 1, out, 48) == -1);
    ASSERT_TRUE(tinysha_sha512(nullptr, 1, out, 64) == -1);
    ASSERT_TRUE(tinysha_sha3_256(nullptr, 1, out, 32) == -1);
    ASSERT_TRUE(tinysha_sha3_384(nullptr, 1, out, 48) == -1);
    ASSERT_TRUE(tinysha_sha3_512(nullptr, 1, out, 64) == -1);
}

TEST(hash_c_api_null_data_zero_len)
{
    // data=NULL with data_len=0 is valid (empty input)
    uint8_t out256[32], out384[48], out512[64];
    uint8_t out3_256[32], out3_384[48], out3_512[64];
    ASSERT_TRUE(tinysha_sha256(nullptr, 0, out256, 32) == 0);
    ASSERT_TRUE(tinysha_sha384(nullptr, 0, out384, 48) == 0);
    ASSERT_TRUE(tinysha_sha512(nullptr, 0, out512, 64) == 0);
    ASSERT_TRUE(tinysha_sha3_256(nullptr, 0, out3_256, 32) == 0);
    ASSERT_TRUE(tinysha_sha3_384(nullptr, 0, out3_384, 48) == 0);
    ASSERT_TRUE(tinysha_sha3_512(nullptr, 0, out3_512, 64) == 0);

    // Verify against known empty-input digests via C++ API
    auto e256 = tinysha::sha256({});
    auto e384 = tinysha::sha384({});
    auto e512 = tinysha::sha512({});
    auto e3_256 = tinysha::sha3_256({});
    auto e3_384 = tinysha::sha3_384({});
    auto e3_512 = tinysha::sha3_512({});
    ASSERT_EQ(std::vector<uint8_t>(out256, out256 + 32), e256);
    ASSERT_EQ(std::vector<uint8_t>(out384, out384 + 48), e384);
    ASSERT_EQ(std::vector<uint8_t>(out512, out512 + 64), e512);
    ASSERT_EQ(std::vector<uint8_t>(out3_256, out3_256 + 32), e3_256);
    ASSERT_EQ(std::vector<uint8_t>(out3_384, out3_384 + 48), e3_384);
    ASSERT_EQ(std::vector<uint8_t>(out3_512, out3_512 + 64), e3_512);
}

// ── HMAC C API negative tests ──────────────────────────────────────────────

TEST(hmac_c_api_null_out)
{
    const uint8_t key[] = {0x0b};
    const uint8_t data[] = {0x61};
    ASSERT_TRUE(tinysha_hmac_sha256(key, 1, data, 1, nullptr, 32) == -1);
    ASSERT_TRUE(tinysha_hmac_sha512(key, 1, data, 1, nullptr, 64) == -1);
}

TEST(hmac_c_api_null_key_nonzero_len)
{
    const uint8_t data[] = {0x61};
    uint8_t out[64];
    ASSERT_TRUE(tinysha_hmac_sha256(nullptr, 1, data, 1, out, 32) == -1);
    ASSERT_TRUE(tinysha_hmac_sha512(nullptr, 1, data, 1, out, 64) == -1);
}

TEST(hmac_c_api_null_data_nonzero_len)
{
    const uint8_t key[] = {0x0b};
    uint8_t out[64];
    ASSERT_TRUE(tinysha_hmac_sha256(key, 1, nullptr, 1, out, 32) == -1);
    ASSERT_TRUE(tinysha_hmac_sha512(key, 1, nullptr, 1, out, 64) == -1);
}

TEST(hmac_c_api_zero_out_len)
{
    const uint8_t key[] = {0x0b};
    const uint8_t data[] = {0x61};
    uint8_t out[64];
    ASSERT_TRUE(tinysha_hmac_sha256(key, 1, data, 1, out, 0) == -1);
    ASSERT_TRUE(tinysha_hmac_sha512(key, 1, data, 1, out, 0) == -1);
}

TEST(hmac_c_api_out_len_too_large)
{
    const uint8_t key[] = {0x0b};
    const uint8_t data[] = {0x61};
    uint8_t out[128];
    ASSERT_TRUE(tinysha_hmac_sha256(key, 1, data, 1, out, 33) == -1);
    ASSERT_TRUE(tinysha_hmac_sha512(key, 1, data, 1, out, 65) == -1);
}

// ── PBKDF2 C API negative tests ───────────────────────────────────────────

TEST(pbkdf2_c_api_null_out)
{
    const uint8_t pw[] = {0x70};
    const uint8_t salt[] = {0x73};
    ASSERT_TRUE(tinysha_pbkdf2_sha256(pw, 1, salt, 1, 1, nullptr, 32) == -1);
}

TEST(pbkdf2_c_api_zero_dk_len)
{
    const uint8_t pw[] = {0x70};
    const uint8_t salt[] = {0x73};
    uint8_t out[32];
    ASSERT_TRUE(tinysha_pbkdf2_sha256(pw, 1, salt, 1, 1, out, 0) == -1);
}

TEST(pbkdf2_c_api_zero_iterations)
{
    const uint8_t pw[] = {0x70};
    const uint8_t salt[] = {0x73};
    uint8_t out[32];
    ASSERT_TRUE(tinysha_pbkdf2_sha256(pw, 1, salt, 1, 0, out, 32) == -1);
}

TEST(pbkdf2_c_api_null_password_nonzero_len)
{
    const uint8_t salt[] = {0x73};
    uint8_t out[32];
    ASSERT_TRUE(tinysha_pbkdf2_sha256(nullptr, 1, salt, 1, 1, out, 32) == -1);
}

TEST(pbkdf2_c_api_null_salt_nonzero_len)
{
    const uint8_t pw[] = {0x70};
    uint8_t out[32];
    ASSERT_TRUE(tinysha_pbkdf2_sha256(pw, 1, nullptr, 1, 1, out, 32) == -1);
}

// ── constant_time_equal tests ──────────────────────────────────────────────

TEST(constant_time_equal_same)
{
    const uint8_t a[] = {0x01, 0x02, 0x03, 0x04};
    const uint8_t b[] = {0x01, 0x02, 0x03, 0x04};
    ASSERT_TRUE(tinysha::constant_time_equal(a, b, 4));
}

TEST(constant_time_equal_differ)
{
    const uint8_t a[] = {0x01, 0x02, 0x03, 0x04};
    const uint8_t b[] = {0x01, 0x02, 0x03, 0x05};
    ASSERT_TRUE(!tinysha::constant_time_equal(a, b, 4));
}

TEST(constant_time_equal_empty)
{
    ASSERT_TRUE(tinysha::constant_time_equal(nullptr, nullptr, 0));
}

TEST(constant_time_equal_vector_same)
{
    std::vector<uint8_t> a = {0xaa, 0xbb, 0xcc};
    std::vector<uint8_t> b = {0xaa, 0xbb, 0xcc};
    ASSERT_TRUE(tinysha::constant_time_equal(a, b));
}

TEST(constant_time_equal_vector_different_len)
{
    std::vector<uint8_t> a = {0xaa, 0xbb};
    std::vector<uint8_t> b = {0xaa, 0xbb, 0xcc};
    ASSERT_TRUE(!tinysha::constant_time_equal(a, b));
}

TEST(constant_time_equal_c_api)
{
    const uint8_t a[] = {0x01, 0x02, 0x03};
    const uint8_t b[] = {0x01, 0x02, 0x03};
    const uint8_t c[] = {0x01, 0x02, 0x04};
    ASSERT_TRUE(tinysha_constant_time_equal(a, b, 3) == 1);
    ASSERT_TRUE(tinysha_constant_time_equal(a, c, 3) == 0);
}
