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

#include "tinysha/pbkdf2.h"

#include "tinysha/sha256.h"
#include "tinysha/sha384.h"
#include "tinysha/sha3_256.h"
#include "tinysha/sha3_384.h"
#include "tinysha/sha3_512.h"
#include "tinysha/sha512.h"

#include <cstring>

template<typename T>
static int pbkdf2_c_api(
    const uint8_t *password,
    size_t password_len,
    const uint8_t *salt,
    size_t salt_len,
    uint32_t iterations,
    uint8_t *out,
    size_t dk_len)
{
    if (!out || dk_len == 0)
        return -1;
    if (!password && password_len > 0)
        return -1;
    if (!salt && salt_len > 0)
        return -1;
    if (iterations == 0)
        return -1;
    std::vector<uint8_t> pw(password_len);
    if (password_len > 0)
        std::memcpy(pw.data(), password, password_len);
    std::vector<uint8_t> s(salt_len);
    if (salt_len > 0)
        std::memcpy(s.data(), salt, salt_len);
    auto result = tinysha::pbkdf2<T>(pw, s, iterations, dk_len);
    std::memcpy(out, result.data(), dk_len);
    tinysha::secure_zero(pw.data(), pw.size());
    tinysha::secure_zero(s.data(), s.size());
    tinysha::secure_zero(result.data(), result.size());
    return 0;
}

extern "C"
{
    int tinysha_pbkdf2_sha256(
        const uint8_t *password,
        size_t password_len,
        const uint8_t *salt,
        size_t salt_len,
        uint32_t iterations,
        uint8_t *out,
        size_t dk_len)
    {
        return pbkdf2_c_api<tinysha::SHA256Traits>(password, password_len, salt, salt_len, iterations, out, dk_len);
    }

    int tinysha_pbkdf2_sha384(
        const uint8_t *password,
        size_t password_len,
        const uint8_t *salt,
        size_t salt_len,
        uint32_t iterations,
        uint8_t *out,
        size_t dk_len)
    {
        return pbkdf2_c_api<tinysha::SHA384Traits>(password, password_len, salt, salt_len, iterations, out, dk_len);
    }

    int tinysha_pbkdf2_sha512(
        const uint8_t *password,
        size_t password_len,
        const uint8_t *salt,
        size_t salt_len,
        uint32_t iterations,
        uint8_t *out,
        size_t dk_len)
    {
        return pbkdf2_c_api<tinysha::SHA512Traits>(password, password_len, salt, salt_len, iterations, out, dk_len);
    }

    int tinysha_pbkdf2_sha3_256(
        const uint8_t *password,
        size_t password_len,
        const uint8_t *salt,
        size_t salt_len,
        uint32_t iterations,
        uint8_t *out,
        size_t dk_len)
    {
        return pbkdf2_c_api<tinysha::SHA3_256Traits>(password, password_len, salt, salt_len, iterations, out, dk_len);
    }

    int tinysha_pbkdf2_sha3_384(
        const uint8_t *password,
        size_t password_len,
        const uint8_t *salt,
        size_t salt_len,
        uint32_t iterations,
        uint8_t *out,
        size_t dk_len)
    {
        return pbkdf2_c_api<tinysha::SHA3_384Traits>(password, password_len, salt, salt_len, iterations, out, dk_len);
    }

    int tinysha_pbkdf2_sha3_512(
        const uint8_t *password,
        size_t password_len,
        const uint8_t *salt,
        size_t salt_len,
        uint32_t iterations,
        uint8_t *out,
        size_t dk_len)
    {
        return pbkdf2_c_api<tinysha::SHA3_512Traits>(password, password_len, salt, salt_len, iterations, out, dk_len);
    }
}
