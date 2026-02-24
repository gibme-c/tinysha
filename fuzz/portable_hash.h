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

// Portable-only hash implementations for differential fuzzing.
// These call the portable backends directly, bypassing CPUID dispatch,
// so we can compare portable output against dispatch output.

#include "internal/endian.h"
#include "tinysha/common.h"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <vector>

namespace tinysha::internal
{
    extern void sha256_compress_portable(uint32_t state[8], const uint8_t block[64]);
    extern void sha512_compress_portable(uint64_t state[8], const uint8_t block[128]);
    extern void keccak_f1600_portable(uint64_t state[25]);
} // namespace tinysha::internal

namespace portable
{

    inline std::vector<uint8_t> sha256(const uint8_t *data, size_t len)
    {
        uint32_t state[8] = {
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19,
        };

        size_t offset = 0;
        while (offset + 64 <= len)
        {
            tinysha::internal::sha256_compress_portable(state, data + offset);
            offset += 64;
        }

        uint8_t block[64];
        size_t remaining = len - offset;
        std::memcpy(block, data + offset, remaining);
        block[remaining] = 0x80;
        remaining++;

        if (remaining > 56)
        {
            std::memset(block + remaining, 0, 64 - remaining);
            tinysha::internal::sha256_compress_portable(state, block);
            std::memset(block, 0, 56);
        }
        else
        {
            std::memset(block + remaining, 0, 56 - remaining);
        }

        uint64_t bit_len = static_cast<uint64_t>(len) * 8;
        tinysha::internal::store_be64(block + 56, bit_len);
        tinysha::internal::sha256_compress_portable(state, block);

        std::vector<uint8_t> digest(32);
        for (int i = 0; i < 8; ++i)
            tinysha::internal::store_be32(digest.data() + i * 4, state[i]);
        return digest;
    }

    inline std::vector<uint8_t> sha512(const uint8_t *data, size_t len, size_t digest_bytes = 64)
    {
        uint64_t state[8] = {
            0x6a09e667f3bcc908ULL,
            0xbb67ae8584caa73bULL,
            0x3c6ef372fe94f82bULL,
            0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL,
            0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb41bd6bULL,
            0x5be0cd19137e2179ULL,
        };

        size_t offset = 0;
        while (offset + 128 <= len)
        {
            tinysha::internal::sha512_compress_portable(state, data + offset);
            offset += 128;
        }

        uint8_t block[128];
        size_t remaining = len - offset;
        std::memcpy(block, data + offset, remaining);
        block[remaining] = 0x80;
        remaining++;

        if (remaining > 112)
        {
            std::memset(block + remaining, 0, 128 - remaining);
            tinysha::internal::sha512_compress_portable(state, block);
            std::memset(block, 0, 112);
        }
        else
        {
            std::memset(block + remaining, 0, 112 - remaining);
        }

        std::memset(block + 112, 0, 8);
        uint64_t bit_len = static_cast<uint64_t>(len) * 8;
        tinysha::internal::store_be64(block + 120, bit_len);
        tinysha::internal::sha512_compress_portable(state, block);

        std::vector<uint8_t> digest(digest_bytes);
        size_t full_words = digest_bytes / 8;
        for (size_t i = 0; i < full_words; ++i)
            tinysha::internal::store_be64(digest.data() + i * 8, state[i]);
        if (digest_bytes % 8 != 0)
        {
            uint8_t tmp[8];
            tinysha::internal::store_be64(tmp, state[full_words]);
            std::memcpy(digest.data() + full_words * 8, tmp, digest_bytes % 8);
        }
        return digest;
    }

    inline std::vector<uint8_t> sha384(const uint8_t *data, size_t len)
    {
        // SHA-384 = SHA-512 with different IVs, truncated to 48 bytes.
        // Temporarily swap IVs, compute, restore — or just inline.
        uint64_t state[8] = {
            0xcbbb9d5dc1059ed8ULL,
            0x629a292a367cd507ULL,
            0x9159015a3070dd17ULL,
            0x152fecd8f70e5939ULL,
            0x67332667ffc00b31ULL,
            0x8eb44a8768581511ULL,
            0xdb0c2e0d64f98fa7ULL,
            0x47b5481dbefa4fa4ULL,
        };

        size_t offset = 0;
        while (offset + 128 <= len)
        {
            tinysha::internal::sha512_compress_portable(state, data + offset);
            offset += 128;
        }

        uint8_t block[128];
        size_t remaining = len - offset;
        std::memcpy(block, data + offset, remaining);
        block[remaining] = 0x80;
        remaining++;

        if (remaining > 112)
        {
            std::memset(block + remaining, 0, 128 - remaining);
            tinysha::internal::sha512_compress_portable(state, block);
            std::memset(block, 0, 112);
        }
        else
        {
            std::memset(block + remaining, 0, 112 - remaining);
        }

        std::memset(block + 112, 0, 8);
        uint64_t bit_len = static_cast<uint64_t>(len) * 8;
        tinysha::internal::store_be64(block + 120, bit_len);
        tinysha::internal::sha512_compress_portable(state, block);

        std::vector<uint8_t> digest(48);
        for (int i = 0; i < 6; ++i)
            tinysha::internal::store_be64(digest.data() + i * 8, state[i]);
        return digest;
    }

    inline std::vector<uint8_t> sha3_sponge(const uint8_t *data, size_t len, size_t rate_bytes, size_t digest_bytes)
    {
        uint64_t state[25] = {};
        size_t offset = 0;

        while (offset + rate_bytes <= len)
        {
            for (size_t i = 0; i < rate_bytes / 8; ++i)
                state[i] ^= tinysha::internal::load_le64(data + offset + i * 8);
            tinysha::internal::keccak_f1600_portable(state);
            offset += rate_bytes;
        }

        size_t remaining = len - offset;
        uint8_t block[200] = {};
        std::memcpy(block, data + offset, remaining);
        block[remaining] = 0x06;
        block[rate_bytes - 1] |= 0x80;

        for (size_t i = 0; i < rate_bytes / 8; ++i)
            state[i] ^= tinysha::internal::load_le64(block + i * 8);
        tinysha::internal::keccak_f1600_portable(state);

        std::vector<uint8_t> digest(digest_bytes);
        size_t squeezed = 0;
        while (squeezed < digest_bytes)
        {
            size_t to_copy = digest_bytes - squeezed;
            if (to_copy > rate_bytes)
                to_copy = rate_bytes;

            size_t full_lanes = to_copy / 8;
            for (size_t i = 0; i < full_lanes; ++i)
                tinysha::internal::store_le64(digest.data() + squeezed + i * 8, state[i]);
            if (to_copy % 8 != 0)
            {
                uint8_t tmp[8];
                tinysha::internal::store_le64(tmp, state[full_lanes]);
                std::memcpy(digest.data() + squeezed + full_lanes * 8, tmp, to_copy % 8);
            }

            squeezed += to_copy;
            if (squeezed < digest_bytes)
                tinysha::internal::keccak_f1600_portable(state);
        }
        return digest;
    }

    inline std::vector<uint8_t> sha3_256(const uint8_t *data, size_t len)
    {
        return sha3_sponge(data, len, 136, 32);
    }
    inline std::vector<uint8_t> sha3_384(const uint8_t *data, size_t len)
    {
        return sha3_sponge(data, len, 104, 48);
    }
    inline std::vector<uint8_t> sha3_512(const uint8_t *data, size_t len)
    {
        return sha3_sponge(data, len, 72, 64);
    }

    // Portable traits for use with tinysha::hmac<> and tinysha::pbkdf2<> templates
    struct SHA256Traits
    {
        static constexpr size_t digest_size = 32;
        static constexpr size_t block_size = 64;
        static std::vector<uint8_t> hash(const std::vector<uint8_t> &d)
        {
            return sha256(d.data(), d.size());
        }
    };

    struct SHA384Traits
    {
        static constexpr size_t digest_size = 48;
        static constexpr size_t block_size = 128;
        static std::vector<uint8_t> hash(const std::vector<uint8_t> &d)
        {
            return sha384(d.data(), d.size());
        }
    };

    struct SHA512Traits
    {
        static constexpr size_t digest_size = 64;
        static constexpr size_t block_size = 128;
        static std::vector<uint8_t> hash(const std::vector<uint8_t> &d)
        {
            return sha512(d.data(), d.size());
        }
    };

    struct SHA3_256Traits
    {
        static constexpr size_t digest_size = 32;
        static constexpr size_t block_size = 136;
        static std::vector<uint8_t> hash(const std::vector<uint8_t> &d)
        {
            return sha3_256(d.data(), d.size());
        }
    };

    struct SHA3_384Traits
    {
        static constexpr size_t digest_size = 48;
        static constexpr size_t block_size = 104;
        static std::vector<uint8_t> hash(const std::vector<uint8_t> &d)
        {
            return sha3_384(d.data(), d.size());
        }
    };

    struct SHA3_512Traits
    {
        static constexpr size_t digest_size = 64;
        static constexpr size_t block_size = 72;
        static std::vector<uint8_t> hash(const std::vector<uint8_t> &d)
        {
            return sha3_512(d.data(), d.size());
        }
    };

} // namespace portable
