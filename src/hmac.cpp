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

#include "tinysha/hmac.h"

#include "tinysha/sha256.h"
#include "tinysha/sha384.h"
#include "tinysha/sha3_256.h"
#include "tinysha/sha3_384.h"
#include "tinysha/sha3_512.h"
#include "tinysha/sha512.h"

#include <cstring>

static int hmac_c_api_impl(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *data,
    size_t data_len,
    uint8_t *out,
    size_t out_len,
    size_t max_digest,
    std::vector<uint8_t> (*fn)(const std::vector<uint8_t> &, const std::vector<uint8_t> &))
{
    if (!out || out_len == 0 || out_len > max_digest)
        return -1;
    if (!key && key_len > 0)
        return -1;
    if (!data && data_len > 0)
        return -1;
    std::vector<uint8_t> k(key, key + key_len);
    std::vector<uint8_t> d(data, data + data_len);
    auto result = fn(k, d);
    std::memcpy(out, result.data(), out_len);
    tinysha::secure_zero(k.data(), k.size());
    tinysha::secure_zero(d.data(), d.size());
    tinysha::secure_zero(result.data(), result.size());
    return 0;
}

template<typename T>
static std::vector<uint8_t> hmac_wrap(const std::vector<uint8_t> &key, const std::vector<uint8_t> &data)
{
    return tinysha::hmac<T>(key, data);
}

extern "C"
{
    int tinysha_hmac_sha256(
        const uint8_t *key,
        size_t key_len,
        const uint8_t *data,
        size_t data_len,
        uint8_t *out,
        size_t out_len)
    {
        return hmac_c_api_impl(key, key_len, data, data_len, out, out_len, 32, hmac_wrap<tinysha::SHA256Traits>);
    }

    int tinysha_hmac_sha384(
        const uint8_t *key,
        size_t key_len,
        const uint8_t *data,
        size_t data_len,
        uint8_t *out,
        size_t out_len)
    {
        return hmac_c_api_impl(key, key_len, data, data_len, out, out_len, 48, hmac_wrap<tinysha::SHA384Traits>);
    }

    int tinysha_hmac_sha512(
        const uint8_t *key,
        size_t key_len,
        const uint8_t *data,
        size_t data_len,
        uint8_t *out,
        size_t out_len)
    {
        return hmac_c_api_impl(key, key_len, data, data_len, out, out_len, 64, hmac_wrap<tinysha::SHA512Traits>);
    }

    int tinysha_hmac_sha3_256(
        const uint8_t *key,
        size_t key_len,
        const uint8_t *data,
        size_t data_len,
        uint8_t *out,
        size_t out_len)
    {
        return hmac_c_api_impl(key, key_len, data, data_len, out, out_len, 32, hmac_wrap<tinysha::SHA3_256Traits>);
    }

    int tinysha_hmac_sha3_384(
        const uint8_t *key,
        size_t key_len,
        const uint8_t *data,
        size_t data_len,
        uint8_t *out,
        size_t out_len)
    {
        return hmac_c_api_impl(key, key_len, data, data_len, out, out_len, 48, hmac_wrap<tinysha::SHA3_384Traits>);
    }

    int tinysha_hmac_sha3_512(
        const uint8_t *key,
        size_t key_len,
        const uint8_t *data,
        size_t data_len,
        uint8_t *out,
        size_t out_len)
    {
        return hmac_c_api_impl(key, key_len, data, data_len, out, out_len, 64, hmac_wrap<tinysha::SHA3_512Traits>);
    }
}
