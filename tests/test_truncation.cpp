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

TEST(sha256_truncation)
{
    std::vector<uint8_t> data = {0x61, 0x62, 0x63};
    auto full = tinysha::sha256(data);
    auto trunc = tinysha::sha256(data, 16);
    ASSERT_TRUE(trunc.size() == 16);
    std::vector<uint8_t> expected(full.begin(), full.begin() + 16);
    ASSERT_EQ(trunc, expected);
}

TEST(sha512_truncation)
{
    std::vector<uint8_t> data = {0x61, 0x62, 0x63};
    auto full = tinysha::sha512(data);
    auto trunc = tinysha::sha512(data, 20);
    ASSERT_TRUE(trunc.size() == 20);
    std::vector<uint8_t> expected(full.begin(), full.begin() + 20);
    ASSERT_EQ(trunc, expected);
}

TEST(sha3_256_truncation)
{
    std::vector<uint8_t> data = {0x61, 0x62, 0x63};
    auto full = tinysha::sha3_256(data);
    auto trunc = tinysha::sha3_256(data, 12);
    ASSERT_TRUE(trunc.size() == 12);
    std::vector<uint8_t> expected(full.begin(), full.begin() + 12);
    ASSERT_EQ(trunc, expected);
}

TEST(hmac_truncation)
{
    std::vector<uint8_t> key = {0x0b, 0x0b, 0x0b, 0x0b};
    std::vector<uint8_t> data = {0x48, 0x69};
    auto full = tinysha::hmac<tinysha::SHA256Traits>(key, data);
    auto trunc = tinysha::hmac<tinysha::SHA256Traits>(key, data, 10);
    ASSERT_TRUE(trunc.size() == 10);
    std::vector<uint8_t> expected(full.begin(), full.begin() + 10);
    ASSERT_EQ(trunc, expected);
}