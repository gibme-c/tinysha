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
#include "vectors/pbkdf2_vectors.inl"

#include <tinysha.h>

// ── PBKDF2-SHA-256 ────────────────────────────────────────────────────────

TEST(pbkdf2_sha256_vectors)
{
    for (size_t i = 0; i < pbkdf2_sha256_vector_count; ++i)
    {
        const auto &v = pbkdf2_sha256_vectors[i];
        std::vector<uint8_t> pw(v.password, v.password + v.password_len);
        std::vector<uint8_t> salt(v.salt, v.salt + v.salt_len);
        auto dk = tinysha::pbkdf2<tinysha::SHA256Traits>(pw, salt, v.iterations, v.dk_len);
        std::vector<uint8_t> expected(v.expected, v.expected + v.expected_len);
        ASSERT_EQ(dk, expected);
    }
}

TEST(pbkdf2_sha256_c_api)
{
    const auto &v = pbkdf2_sha256_vectors[0];
    std::vector<uint8_t> out(v.dk_len);
    int rc = tinysha_pbkdf2_sha256(v.password, v.password_len, v.salt, v.salt_len, v.iterations, out.data(), v.dk_len);
    ASSERT_TRUE(rc == 0);
    std::vector<uint8_t> expected(v.expected, v.expected + v.expected_len);
    ASSERT_EQ(out, expected);
}

// ── PBKDF2-SHA-384 ────────────────────────────────────────────────────────

TEST(pbkdf2_sha384_vectors)
{
    for (size_t i = 0; i < pbkdf2_sha384_vector_count; ++i)
    {
        const auto &v = pbkdf2_sha384_vectors[i];
        std::vector<uint8_t> pw(v.password, v.password + v.password_len);
        std::vector<uint8_t> salt(v.salt, v.salt + v.salt_len);
        auto dk = tinysha::pbkdf2<tinysha::SHA384Traits>(pw, salt, v.iterations, v.dk_len);
        std::vector<uint8_t> expected(v.expected, v.expected + v.expected_len);
        ASSERT_EQ(dk, expected);
    }
}

TEST(pbkdf2_sha384_c_api)
{
    const auto &v = pbkdf2_sha384_vectors[0];
    std::vector<uint8_t> out(v.dk_len);
    int rc = tinysha_pbkdf2_sha384(v.password, v.password_len, v.salt, v.salt_len, v.iterations, out.data(), v.dk_len);
    ASSERT_TRUE(rc == 0);
    std::vector<uint8_t> expected(v.expected, v.expected + v.expected_len);
    ASSERT_EQ(out, expected);
}

// ── PBKDF2-SHA-512 ────────────────────────────────────────────────────────

TEST(pbkdf2_sha512_vectors)
{
    for (size_t i = 0; i < pbkdf2_sha512_vector_count; ++i)
    {
        const auto &v = pbkdf2_sha512_vectors[i];
        std::vector<uint8_t> pw(v.password, v.password + v.password_len);
        std::vector<uint8_t> salt(v.salt, v.salt + v.salt_len);
        auto dk = tinysha::pbkdf2<tinysha::SHA512Traits>(pw, salt, v.iterations, v.dk_len);
        std::vector<uint8_t> expected(v.expected, v.expected + v.expected_len);
        ASSERT_EQ(dk, expected);
    }
}

TEST(pbkdf2_sha512_c_api)
{
    const auto &v = pbkdf2_sha512_vectors[0];
    std::vector<uint8_t> out(v.dk_len);
    int rc = tinysha_pbkdf2_sha512(v.password, v.password_len, v.salt, v.salt_len, v.iterations, out.data(), v.dk_len);
    ASSERT_TRUE(rc == 0);
    std::vector<uint8_t> expected(v.expected, v.expected + v.expected_len);
    ASSERT_EQ(out, expected);
}

// ── PBKDF2-SHA3-256 ───────────────────────────────────────────────────────

TEST(pbkdf2_sha3_256_vectors)
{
    for (size_t i = 0; i < pbkdf2_sha3_256_vector_count; ++i)
    {
        const auto &v = pbkdf2_sha3_256_vectors[i];
        std::vector<uint8_t> pw(v.password, v.password + v.password_len);
        std::vector<uint8_t> salt(v.salt, v.salt + v.salt_len);
        auto dk = tinysha::pbkdf2<tinysha::SHA3_256Traits>(pw, salt, v.iterations, v.dk_len);
        std::vector<uint8_t> expected(v.expected, v.expected + v.expected_len);
        ASSERT_EQ(dk, expected);
    }
}

TEST(pbkdf2_sha3_256_c_api)
{
    const auto &v = pbkdf2_sha3_256_vectors[0];
    std::vector<uint8_t> out(v.dk_len);
    int rc =
        tinysha_pbkdf2_sha3_256(v.password, v.password_len, v.salt, v.salt_len, v.iterations, out.data(), v.dk_len);
    ASSERT_TRUE(rc == 0);
    std::vector<uint8_t> expected(v.expected, v.expected + v.expected_len);
    ASSERT_EQ(out, expected);
}

// ── PBKDF2-SHA3-384 ───────────────────────────────────────────────────────

TEST(pbkdf2_sha3_384_vectors)
{
    for (size_t i = 0; i < pbkdf2_sha3_384_vector_count; ++i)
    {
        const auto &v = pbkdf2_sha3_384_vectors[i];
        std::vector<uint8_t> pw(v.password, v.password + v.password_len);
        std::vector<uint8_t> salt(v.salt, v.salt + v.salt_len);
        auto dk = tinysha::pbkdf2<tinysha::SHA3_384Traits>(pw, salt, v.iterations, v.dk_len);
        std::vector<uint8_t> expected(v.expected, v.expected + v.expected_len);
        ASSERT_EQ(dk, expected);
    }
}

TEST(pbkdf2_sha3_384_c_api)
{
    const auto &v = pbkdf2_sha3_384_vectors[0];
    std::vector<uint8_t> out(v.dk_len);
    int rc =
        tinysha_pbkdf2_sha3_384(v.password, v.password_len, v.salt, v.salt_len, v.iterations, out.data(), v.dk_len);
    ASSERT_TRUE(rc == 0);
    std::vector<uint8_t> expected(v.expected, v.expected + v.expected_len);
    ASSERT_EQ(out, expected);
}

// ── PBKDF2-SHA3-512 ───────────────────────────────────────────────────────

TEST(pbkdf2_sha3_512_vectors)
{
    for (size_t i = 0; i < pbkdf2_sha3_512_vector_count; ++i)
    {
        const auto &v = pbkdf2_sha3_512_vectors[i];
        std::vector<uint8_t> pw(v.password, v.password + v.password_len);
        std::vector<uint8_t> salt(v.salt, v.salt + v.salt_len);
        auto dk = tinysha::pbkdf2<tinysha::SHA3_512Traits>(pw, salt, v.iterations, v.dk_len);
        std::vector<uint8_t> expected(v.expected, v.expected + v.expected_len);
        ASSERT_EQ(dk, expected);
    }
}

TEST(pbkdf2_sha3_512_c_api)
{
    const auto &v = pbkdf2_sha3_512_vectors[0];
    std::vector<uint8_t> out(v.dk_len);
    int rc =
        tinysha_pbkdf2_sha3_512(v.password, v.password_len, v.salt, v.salt_len, v.iterations, out.data(), v.dk_len);
    ASSERT_TRUE(rc == 0);
    std::vector<uint8_t> expected(v.expected, v.expected + v.expected_len);
    ASSERT_EQ(out, expected);
}
