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
#include "hmac.h"

#include <cstring>

#ifdef __cplusplus
extern "C"
{
#endif

    TINYSHA_EXPORT int tinysha_pbkdf2_sha256(
        const uint8_t *password,
        size_t password_len,
        const uint8_t *salt,
        size_t salt_len,
        uint32_t iterations,
        uint8_t *out,
        size_t dk_len);
    TINYSHA_EXPORT int tinysha_pbkdf2_sha384(
        const uint8_t *password,
        size_t password_len,
        const uint8_t *salt,
        size_t salt_len,
        uint32_t iterations,
        uint8_t *out,
        size_t dk_len);
    TINYSHA_EXPORT int tinysha_pbkdf2_sha512(
        const uint8_t *password,
        size_t password_len,
        const uint8_t *salt,
        size_t salt_len,
        uint32_t iterations,
        uint8_t *out,
        size_t dk_len);
    TINYSHA_EXPORT int tinysha_pbkdf2_sha3_256(
        const uint8_t *password,
        size_t password_len,
        const uint8_t *salt,
        size_t salt_len,
        uint32_t iterations,
        uint8_t *out,
        size_t dk_len);
    TINYSHA_EXPORT int tinysha_pbkdf2_sha3_384(
        const uint8_t *password,
        size_t password_len,
        const uint8_t *salt,
        size_t salt_len,
        uint32_t iterations,
        uint8_t *out,
        size_t dk_len);
    TINYSHA_EXPORT int tinysha_pbkdf2_sha3_512(
        const uint8_t *password,
        size_t password_len,
        const uint8_t *salt,
        size_t salt_len,
        uint32_t iterations,
        uint8_t *out,
        size_t dk_len);

#ifdef __cplusplus
}
#endif

namespace tinysha
{

    template<typename HashTraits>
    std::vector<uint8_t> pbkdf2(
        const std::vector<uint8_t> &password,
        const std::vector<uint8_t> &salt,
        uint32_t iterations,
        size_t dk_len)
    {
        constexpr size_t h_len = HashTraits::digest_size;

        // RFC 2898: iterations must be >= 1
        if (iterations == 0 || dk_len == 0)
            return {};

        // RFC 2898: dk_len must be <= (2^32 - 1) * hLen
        if (dk_len > static_cast<size_t>(0xFFFFFFFF) * h_len)
            return {};

        // Note: all vectors in this function are constructed with exact sizes
        // or use reserve() to exact capacity before populating, so
        // secure_zero(v.data(), v.size()) covers all populated bytes.
        std::vector<uint8_t> dk;
        dk.reserve(dk_len);

        uint32_t block_count = static_cast<uint32_t>((dk_len + h_len - 1) / h_len);

        for (uint32_t i = 1; i <= block_count; ++i)
        {
            // U_1 = HMAC(password, salt || INT_32_BE(i))
            std::vector<uint8_t> salt_i;
            salt_i.reserve(salt.size() + 4);
            salt_i.insert(salt_i.end(), salt.begin(), salt.end());
            salt_i.push_back(static_cast<uint8_t>(i >> 24));
            salt_i.push_back(static_cast<uint8_t>(i >> 16));
            salt_i.push_back(static_cast<uint8_t>(i >> 8));
            salt_i.push_back(static_cast<uint8_t>(i));

            auto u = hmac<HashTraits>(password, salt_i);
            secure_zero(salt_i.data(), salt_i.size());

            std::vector<uint8_t> t = u;

            // U_2 .. U_c
            for (uint32_t j = 1; j < iterations; ++j)
            {
                auto u_next = hmac<HashTraits>(password, u);
                secure_zero(u.data(), u.size());
                u = u_next;
                for (size_t k = 0; k < h_len; ++k)
                    t[k] ^= u[k];
            }

            secure_zero(u.data(), u.size());

            size_t remaining = dk_len - dk.size();
            size_t to_copy = remaining < h_len ? remaining : h_len;
            dk.insert(dk.end(), t.begin(), t.begin() + static_cast<std::ptrdiff_t>(to_copy));
            secure_zero(t.data(), t.size());
        }

        return dk;
    }

} // namespace tinysha
