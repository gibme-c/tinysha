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

// ── HMAC-SHA-256 ──────────────────────────────────────────────────────────

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

// ── HMAC-SHA-384 ──────────────────────────────────────────────────────────

TEST(hmac_sha384_rfc4231)
{
    for (size_t i = 0; i < hmac_vector_count; ++i)
    {
        const auto &v = hmac_vectors[i];
        std::vector<uint8_t> key(v.key, v.key + v.key_len);
        std::vector<uint8_t> data(v.data, v.data + v.data_len);
        auto mac = tinysha::hmac<tinysha::SHA384Traits>(key, data);
        std::vector<uint8_t> expected(v.expected_sha384, v.expected_sha384 + 48);
        ASSERT_EQ(mac, expected);
    }
}

TEST(hmac_sha384_c_api)
{
    const auto &v = hmac_vectors[0];
    uint8_t out[48];
    int rc = tinysha_hmac_sha384(v.key, v.key_len, v.data, v.data_len, out, 48);
    ASSERT_TRUE(rc == 0);
    std::vector<uint8_t> result(out, out + 48);
    std::vector<uint8_t> expected(v.expected_sha384, v.expected_sha384 + 48);
    ASSERT_EQ(result, expected);
}

// ── HMAC-SHA-512 ──────────────────────────────────────────────────────────

TEST(hmac_sha512_rfc4231)
{
    for (size_t i = 0; i < hmac_vector_count; ++i)
    {
        const auto &v = hmac_vectors[i];
        std::vector<uint8_t> key(v.key, v.key + v.key_len);
        std::vector<uint8_t> data(v.data, v.data + v.data_len);
        auto mac = tinysha::hmac<tinysha::SHA512Traits>(key, data);
        std::vector<uint8_t> expected(v.expected_sha512, v.expected_sha512 + 64);
        ASSERT_EQ(mac, expected);
    }
}

TEST(hmac_sha512_c_api)
{
    const auto &v = hmac_vectors[0];
    uint8_t out[64];
    int rc = tinysha_hmac_sha512(v.key, v.key_len, v.data, v.data_len, out, 64);
    ASSERT_TRUE(rc == 0);
    std::vector<uint8_t> result(out, out + 64);
    std::vector<uint8_t> expected(v.expected_sha512, v.expected_sha512 + 64);
    ASSERT_EQ(result, expected);
}

// ── HMAC-SHA3-256 ─────────────────────────────────────────────────────────

TEST(hmac_sha3_256_vectors)
{
    for (size_t i = 0; i < hmac_vector_count; ++i)
    {
        const auto &v = hmac_vectors[i];
        std::vector<uint8_t> key(v.key, v.key + v.key_len);
        std::vector<uint8_t> data(v.data, v.data + v.data_len);
        auto mac = tinysha::hmac<tinysha::SHA3_256Traits>(key, data);
        std::vector<uint8_t> expected(v.expected_sha3_256, v.expected_sha3_256 + 32);
        ASSERT_EQ(mac, expected);
    }
}

TEST(hmac_sha3_256_c_api)
{
    const auto &v = hmac_vectors[0];
    uint8_t out[32];
    int rc = tinysha_hmac_sha3_256(v.key, v.key_len, v.data, v.data_len, out, 32);
    ASSERT_TRUE(rc == 0);
    std::vector<uint8_t> result(out, out + 32);
    std::vector<uint8_t> expected(v.expected_sha3_256, v.expected_sha3_256 + 32);
    ASSERT_EQ(result, expected);
}

// ── HMAC-SHA3-384 ─────────────────────────────────────────────────────────

TEST(hmac_sha3_384_vectors)
{
    for (size_t i = 0; i < hmac_vector_count; ++i)
    {
        const auto &v = hmac_vectors[i];
        std::vector<uint8_t> key(v.key, v.key + v.key_len);
        std::vector<uint8_t> data(v.data, v.data + v.data_len);
        auto mac = tinysha::hmac<tinysha::SHA3_384Traits>(key, data);
        std::vector<uint8_t> expected(v.expected_sha3_384, v.expected_sha3_384 + 48);
        ASSERT_EQ(mac, expected);
    }
}

TEST(hmac_sha3_384_c_api)
{
    const auto &v = hmac_vectors[0];
    uint8_t out[48];
    int rc = tinysha_hmac_sha3_384(v.key, v.key_len, v.data, v.data_len, out, 48);
    ASSERT_TRUE(rc == 0);
    std::vector<uint8_t> result(out, out + 48);
    std::vector<uint8_t> expected(v.expected_sha3_384, v.expected_sha3_384 + 48);
    ASSERT_EQ(result, expected);
}

// ── HMAC-SHA3-512 ─────────────────────────────────────────────────────────

TEST(hmac_sha3_512_vectors)
{
    for (size_t i = 0; i < hmac_vector_count; ++i)
    {
        const auto &v = hmac_vectors[i];
        std::vector<uint8_t> key(v.key, v.key + v.key_len);
        std::vector<uint8_t> data(v.data, v.data + v.data_len);
        auto mac = tinysha::hmac<tinysha::SHA3_512Traits>(key, data);
        std::vector<uint8_t> expected(v.expected_sha3_512, v.expected_sha3_512 + 64);
        ASSERT_EQ(mac, expected);
    }
}

TEST(hmac_sha3_512_c_api)
{
    const auto &v = hmac_vectors[0];
    uint8_t out[64];
    int rc = tinysha_hmac_sha3_512(v.key, v.key_len, v.data, v.data_len, out, 64);
    ASSERT_TRUE(rc == 0);
    std::vector<uint8_t> result(out, out + 64);
    std::vector<uint8_t> expected(v.expected_sha3_512, v.expected_sha3_512 + 64);
    ASSERT_EQ(result, expected);
}

// ── HMAC edge cases ───────────────────────────────────────────────────────

TEST(hmac_empty_data)
{
    // HMAC with valid key and empty data — cross-validate C++ vs C API
    const uint8_t key[] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    std::vector<uint8_t> vkey(key, key + 16);
    std::vector<uint8_t> empty_data;

    // SHA-256
    {
        auto cpp = tinysha::hmac<tinysha::SHA256Traits>(vkey, empty_data);
        uint8_t out[32];
        int rc = tinysha_hmac_sha256(key, 16, nullptr, 0, out, 32);
        ASSERT_TRUE(rc == 0);
        ASSERT_EQ(cpp, std::vector<uint8_t>(out, out + 32));
    }
    // SHA-384
    {
        auto cpp = tinysha::hmac<tinysha::SHA384Traits>(vkey, empty_data);
        uint8_t out[48];
        int rc = tinysha_hmac_sha384(key, 16, nullptr, 0, out, 48);
        ASSERT_TRUE(rc == 0);
        ASSERT_EQ(cpp, std::vector<uint8_t>(out, out + 48));
    }
    // SHA-512
    {
        auto cpp = tinysha::hmac<tinysha::SHA512Traits>(vkey, empty_data);
        uint8_t out[64];
        int rc = tinysha_hmac_sha512(key, 16, nullptr, 0, out, 64);
        ASSERT_TRUE(rc == 0);
        ASSERT_EQ(cpp, std::vector<uint8_t>(out, out + 64));
    }
    // SHA3-256
    {
        auto cpp = tinysha::hmac<tinysha::SHA3_256Traits>(vkey, empty_data);
        uint8_t out[32];
        int rc = tinysha_hmac_sha3_256(key, 16, nullptr, 0, out, 32);
        ASSERT_TRUE(rc == 0);
        ASSERT_EQ(cpp, std::vector<uint8_t>(out, out + 32));
    }
    // SHA3-384
    {
        auto cpp = tinysha::hmac<tinysha::SHA3_384Traits>(vkey, empty_data);
        uint8_t out[48];
        int rc = tinysha_hmac_sha3_384(key, 16, nullptr, 0, out, 48);
        ASSERT_TRUE(rc == 0);
        ASSERT_EQ(cpp, std::vector<uint8_t>(out, out + 48));
    }
    // SHA3-512
    {
        auto cpp = tinysha::hmac<tinysha::SHA3_512Traits>(vkey, empty_data);
        uint8_t out[64];
        int rc = tinysha_hmac_sha3_512(key, 16, nullptr, 0, out, 64);
        ASSERT_TRUE(rc == 0);
        ASSERT_EQ(cpp, std::vector<uint8_t>(out, out + 64));
    }
}

TEST(hmac_empty_key)
{
    // HMAC with empty key and valid data — cross-validate C++ vs C API
    std::vector<uint8_t> empty_key;
    const uint8_t data[] = {0x48, 0x69}; // "Hi"
    std::vector<uint8_t> vdata(data, data + 2);

    // SHA-256
    {
        auto cpp = tinysha::hmac<tinysha::SHA256Traits>(empty_key, vdata);
        uint8_t out[32];
        int rc = tinysha_hmac_sha256(nullptr, 0, data, 2, out, 32);
        ASSERT_TRUE(rc == 0);
        ASSERT_EQ(cpp, std::vector<uint8_t>(out, out + 32));
    }
    // SHA-384
    {
        auto cpp = tinysha::hmac<tinysha::SHA384Traits>(empty_key, vdata);
        uint8_t out[48];
        int rc = tinysha_hmac_sha384(nullptr, 0, data, 2, out, 48);
        ASSERT_TRUE(rc == 0);
        ASSERT_EQ(cpp, std::vector<uint8_t>(out, out + 48));
    }
    // SHA-512
    {
        auto cpp = tinysha::hmac<tinysha::SHA512Traits>(empty_key, vdata);
        uint8_t out[64];
        int rc = tinysha_hmac_sha512(nullptr, 0, data, 2, out, 64);
        ASSERT_TRUE(rc == 0);
        ASSERT_EQ(cpp, std::vector<uint8_t>(out, out + 64));
    }
    // SHA3-256
    {
        auto cpp = tinysha::hmac<tinysha::SHA3_256Traits>(empty_key, vdata);
        uint8_t out[32];
        int rc = tinysha_hmac_sha3_256(nullptr, 0, data, 2, out, 32);
        ASSERT_TRUE(rc == 0);
        ASSERT_EQ(cpp, std::vector<uint8_t>(out, out + 32));
    }
    // SHA3-384
    {
        auto cpp = tinysha::hmac<tinysha::SHA3_384Traits>(empty_key, vdata);
        uint8_t out[48];
        int rc = tinysha_hmac_sha3_384(nullptr, 0, data, 2, out, 48);
        ASSERT_TRUE(rc == 0);
        ASSERT_EQ(cpp, std::vector<uint8_t>(out, out + 48));
    }
    // SHA3-512
    {
        auto cpp = tinysha::hmac<tinysha::SHA3_512Traits>(empty_key, vdata);
        uint8_t out[64];
        int rc = tinysha_hmac_sha3_512(nullptr, 0, data, 2, out, 64);
        ASSERT_TRUE(rc == 0);
        ASSERT_EQ(cpp, std::vector<uint8_t>(out, out + 64));
    }
}
