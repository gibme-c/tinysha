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

#pragma once

#include "common.h"

#include <algorithm>
#include <cstring>

#ifdef __cplusplus
extern "C"
{
#endif

    TINYSHA_EXPORT int tinysha_hmac_sha256(
        const uint8_t *key,
        size_t key_len,
        const uint8_t *data,
        size_t data_len,
        uint8_t *out,
        size_t out_len);
    TINYSHA_EXPORT int tinysha_hmac_sha384(
        const uint8_t *key,
        size_t key_len,
        const uint8_t *data,
        size_t data_len,
        uint8_t *out,
        size_t out_len);
    TINYSHA_EXPORT int tinysha_hmac_sha512(
        const uint8_t *key,
        size_t key_len,
        const uint8_t *data,
        size_t data_len,
        uint8_t *out,
        size_t out_len);
    TINYSHA_EXPORT int tinysha_hmac_sha3_256(
        const uint8_t *key,
        size_t key_len,
        const uint8_t *data,
        size_t data_len,
        uint8_t *out,
        size_t out_len);
    TINYSHA_EXPORT int tinysha_hmac_sha3_384(
        const uint8_t *key,
        size_t key_len,
        const uint8_t *data,
        size_t data_len,
        uint8_t *out,
        size_t out_len);
    TINYSHA_EXPORT int tinysha_hmac_sha3_512(
        const uint8_t *key,
        size_t key_len,
        const uint8_t *data,
        size_t data_len,
        uint8_t *out,
        size_t out_len);

#ifdef __cplusplus
}
#endif

namespace tinysha
{

    template<typename HashTraits>
    std::vector<uint8_t> hmac(const std::vector<uint8_t> &key, const std::vector<uint8_t> &data)
    {
        constexpr size_t block_size = HashTraits::block_size;
        constexpr size_t digest_size = HashTraits::digest_size;

        // Step 1: Derive the block-sized key
        // Note: all vectors in this function are constructed with exact sizes
        // (or use reserve() followed by insert() to exact size), so
        // secure_zero(v.data(), v.size()) covers all populated bytes.
        std::vector<uint8_t> k_block(block_size, 0);
        if (key.size() > block_size)
        {
            auto hashed = HashTraits::hash(key);
            std::memcpy(k_block.data(), hashed.data(), digest_size);
            secure_zero(hashed.data(), hashed.size());
        }
        else
        {
            std::memcpy(k_block.data(), key.data(), key.size());
        }

        // Step 2: Inner padding
        std::vector<uint8_t> ipad(block_size);
        for (size_t i = 0; i < block_size; ++i)
            ipad[i] = static_cast<uint8_t>(k_block[i] ^ 0x36);

        // Step 3: Outer padding
        std::vector<uint8_t> opad(block_size);
        for (size_t i = 0; i < block_size; ++i)
            opad[i] = static_cast<uint8_t>(k_block[i] ^ 0x5c);

        secure_zero(k_block.data(), k_block.size());

        // Step 4: inner hash = H(ipad || data)
        std::vector<uint8_t> inner_msg;
        inner_msg.reserve(block_size + data.size());
        inner_msg.insert(inner_msg.end(), ipad.begin(), ipad.end());
        inner_msg.insert(inner_msg.end(), data.begin(), data.end());
        secure_zero(ipad.data(), ipad.size());

        auto inner_hash = HashTraits::hash(inner_msg);
        secure_zero(inner_msg.data(), inner_msg.size());

        // Step 5: outer hash = H(opad || inner_hash)
        std::vector<uint8_t> outer_msg;
        outer_msg.reserve(block_size + digest_size);
        outer_msg.insert(outer_msg.end(), opad.begin(), opad.end());
        outer_msg.insert(outer_msg.end(), inner_hash.begin(), inner_hash.end());
        secure_zero(opad.data(), opad.size());
        secure_zero(inner_hash.data(), inner_hash.size());

        auto result = HashTraits::hash(outer_msg);
        secure_zero(outer_msg.data(), outer_msg.size());

        return result;
    }

    template<typename HashTraits>
    std::vector<uint8_t> hmac(const std::vector<uint8_t> &key, const std::vector<uint8_t> &data, size_t output_len)
    {
        auto full = hmac<HashTraits>(key, data);
        if (output_len < full.size())
        {
            secure_zero(full.data() + output_len, full.size() - output_len);
            full.resize(output_len);
        }
        return full;
    }

} // namespace tinysha
