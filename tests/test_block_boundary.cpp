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

// Generate deterministic test data: byte i = i & 0xff
static std::vector<uint8_t> make_data(size_t len)
{
    std::vector<uint8_t> data(len);
    for (size_t i = 0; i < len; ++i)
        data[i] = static_cast<uint8_t>(i & 0xff);
    return data;
}

// Cross-validate C++ API against C API for a given size
static void check_sha256(size_t len)
{
    auto data = make_data(len);
    auto cpp = tinysha::sha256(data);
    uint8_t out[32];
    int rc = tinysha_sha256(data.data(), data.size(), out, 32);
    ASSERT_TRUE(rc == 0);
    ASSERT_EQ(cpp, std::vector<uint8_t>(out, out + 32));
}

static void check_sha384(size_t len)
{
    auto data = make_data(len);
    auto cpp = tinysha::sha384(data);
    uint8_t out[48];
    int rc = tinysha_sha384(data.data(), data.size(), out, 48);
    ASSERT_TRUE(rc == 0);
    ASSERT_EQ(cpp, std::vector<uint8_t>(out, out + 48));
}

static void check_sha512(size_t len)
{
    auto data = make_data(len);
    auto cpp = tinysha::sha512(data);
    uint8_t out[64];
    int rc = tinysha_sha512(data.data(), data.size(), out, 64);
    ASSERT_TRUE(rc == 0);
    ASSERT_EQ(cpp, std::vector<uint8_t>(out, out + 64));
}

static void check_sha3_256(size_t len)
{
    auto data = make_data(len);
    auto cpp = tinysha::sha3_256(data);
    uint8_t out[32];
    int rc = tinysha_sha3_256(data.data(), data.size(), out, 32);
    ASSERT_TRUE(rc == 0);
    ASSERT_EQ(cpp, std::vector<uint8_t>(out, out + 32));
}

static void check_sha3_384(size_t len)
{
    auto data = make_data(len);
    auto cpp = tinysha::sha3_384(data);
    uint8_t out[48];
    int rc = tinysha_sha3_384(data.data(), data.size(), out, 48);
    ASSERT_TRUE(rc == 0);
    ASSERT_EQ(cpp, std::vector<uint8_t>(out, out + 48));
}

static void check_sha3_512(size_t len)
{
    auto data = make_data(len);
    auto cpp = tinysha::sha3_512(data);
    uint8_t out[64];
    int rc = tinysha_sha3_512(data.data(), data.size(), out, 64);
    ASSERT_TRUE(rc == 0);
    ASSERT_EQ(cpp, std::vector<uint8_t>(out, out + 64));
}

// ── SHA-256 (block_size=64) ───────────────────────────────────────────────

TEST(sha256_block_boundary)
{
    check_sha256(63); // block_size - 1
    check_sha256(64); // block_size
    check_sha256(65); // block_size + 1
    check_sha256(128); // 2 * block_size
    check_sha256(129); // 2 * block_size + 1
    check_sha256(640); // 10 * block_size
}

// ── SHA-384 (block_size=128) ──────────────────────────────────────────────

TEST(sha384_block_boundary)
{
    check_sha384(127);
    check_sha384(128);
    check_sha384(129);
    check_sha384(256);
    check_sha384(257);
    check_sha384(1280);
}

// ── SHA-512 (block_size=128) ──────────────────────────────────────────────

TEST(sha512_block_boundary)
{
    check_sha512(127);
    check_sha512(128);
    check_sha512(129);
    check_sha512(256);
    check_sha512(257);
    check_sha512(1280);
}

// ── SHA3-256 (rate=136) ───────────────────────────────────────────────────

TEST(sha3_256_block_boundary)
{
    check_sha3_256(135);
    check_sha3_256(136);
    check_sha3_256(137);
    check_sha3_256(272);
    check_sha3_256(273);
    check_sha3_256(1360);
}

// ── SHA3-384 (rate=104) ───────────────────────────────────────────────────

TEST(sha3_384_block_boundary)
{
    check_sha3_384(103);
    check_sha3_384(104);
    check_sha3_384(105);
    check_sha3_384(208);
    check_sha3_384(209);
    check_sha3_384(1040);
}

// ── SHA3-512 (rate=72) ────────────────────────────────────────────────────

TEST(sha3_512_block_boundary)
{
    check_sha3_512(71);
    check_sha3_512(72);
    check_sha3_512(73);
    check_sha3_512(144);
    check_sha3_512(145);
    check_sha3_512(720);
}
