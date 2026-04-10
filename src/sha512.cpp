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

#include "tinysha/sha512.h"

#include "cpuid.h"
#include "internal/endian.h"
#include "tinysha/common.h"

#include <atomic>
#include <cstring>

namespace tinysha
{
    namespace internal
    {
        extern void sha512_compress_portable(uint64_t state[8], const uint8_t block[128]);
#if (defined(__x86_64__) || defined(_M_X64)) && !defined(TINYSHA_FORCE_PORTABLE)
        extern void sha512_compress_x64(uint64_t state[8], const uint8_t block[128]);
        extern void sha512_compress_bmi2(uint64_t state[8], const uint8_t block[128]);
        extern void sha512_compress_avx2(uint64_t state[8], const uint8_t block[128]);
        extern void sha512_compress_avx512(uint64_t state[8], const uint8_t block[128]);
#endif
#if (defined(__aarch64__) || defined(_M_ARM64)) && !defined(TINYSHA_FORCE_PORTABLE)
        extern void sha512_compress_arm_ce(uint64_t state[8], const uint8_t block[128]);
#endif
#if !defined(TINYSHA_FORCE_PORTABLE)
        extern CpuFeatures detect_cpu_features();
#endif
    } // namespace internal

    using compress512_fn = void (*)(uint64_t state[8], const uint8_t block[128]);

    static compress512_fn resolve_sha512_compress();
    static std::atomic<compress512_fn> sha512_compress_impl {nullptr};

    static compress512_fn get_sha512_compress()
    {
        auto fn = sha512_compress_impl.load(std::memory_order_acquire);
        if (fn)
            return fn;
        fn = resolve_sha512_compress();
        sha512_compress_impl.store(fn, std::memory_order_release);
        return fn;
    }

    static compress512_fn resolve_sha512_compress()
    {
#if (defined(__x86_64__) || defined(_M_X64)) && !defined(TINYSHA_FORCE_PORTABLE)
        auto features = internal::detect_cpu_features();
        if (features.avx512f)
            return internal::sha512_compress_avx512;
        if (features.avx2 && features.bmi2)
            return internal::sha512_compress_avx2;
        if (features.bmi2)
            return internal::sha512_compress_bmi2;
        return internal::sha512_compress_x64;
#elif (defined(__aarch64__) || defined(_M_ARM64)) && !defined(TINYSHA_FORCE_PORTABLE)
        auto features = internal::detect_cpu_features();
        if (features.arm_sha512)
            return internal::sha512_compress_arm_ce;
        return internal::sha512_compress_portable;
#else
        return internal::sha512_compress_portable;
#endif
    }

    // SHA-512 initial hash values (FIPS 180-4)
    static constexpr uint64_t SHA512_IV[8] = {
        0x6a09e667f3bcc908ULL,
        0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL,
        0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL,
        0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL,
        0x5be0cd19137e2179ULL,
    };

    // Internal: shared SHA-512 engine used by both SHA-512 and SHA-384
    std::vector<uint8_t> sha512_engine(const uint64_t iv[8], const uint8_t *data, size_t len, size_t digest_bytes)
    {
        auto compress = get_sha512_compress();

        uint64_t state[8];
        std::memcpy(state, iv, sizeof(state));

        // Process complete 128-byte blocks
        size_t offset = 0;
        while (offset + 128 <= len)
        {
            compress(state, data + offset);
            offset += 128;
        }

        // Padding
        uint8_t block[128];
        size_t remaining = len - offset;
        if (remaining > 0)
            std::memcpy(block, data + offset, remaining);
        block[remaining] = 0x80;
        remaining++;

        if (remaining > 112)
        {
            std::memset(block + remaining, 0, 128 - remaining);
            compress(state, block);
            std::memset(block, 0, 112);
        }
        else
        {
            std::memset(block + remaining, 0, 112 - remaining);
        }

        // Append big-endian bit length (128-bit, but we only use low 64 bits)
        std::memset(block + 112, 0, 8); // high 64 bits = 0
        uint64_t bit_len = static_cast<uint64_t>(len) * 8;
        internal::store_be64(block + 120, bit_len);
        compress(state, block);

        // Produce output
        std::vector<uint8_t> digest(digest_bytes);
        size_t full_words = digest_bytes / 8;
        for (size_t i = 0; i < full_words; ++i)
            internal::store_be64(digest.data() + i * 8, state[i]);
        // Handle partial last word if digest_bytes is not multiple of 8
        if (digest_bytes % 8 != 0)
        {
            uint8_t tmp[8];
            internal::store_be64(tmp, state[full_words]);
            std::memcpy(digest.data() + full_words * 8, tmp, digest_bytes % 8);
        }

        secure_zero(state, sizeof(state));
        secure_zero(block, sizeof(block));

        return digest;
    }

    std::vector<uint8_t> sha512(const std::vector<uint8_t> &data)
    {
        return sha512_engine(SHA512_IV, data.data(), data.size(), 64);
    }

    std::vector<uint8_t> sha512(const std::vector<uint8_t> &data, size_t output_len)
    {
        auto full = sha512_engine(SHA512_IV, data.data(), data.size(), 64);
        if (output_len < full.size())
        {
            secure_zero(full.data() + output_len, full.size() - output_len);
            full.resize(output_len);
        }
        return full;
    }

    std::vector<uint8_t> SHA512Traits::hash(const std::vector<uint8_t> &data)
    {
        return sha512(data);
    }

} // namespace tinysha

extern "C"
{
    int tinysha_sha512(const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len)
    {
        if (!out || out_len == 0 || out_len > 64)
            return -1;
        if (!data && data_len > 0)
            return -1;
        auto digest = tinysha::sha512_engine(tinysha::SHA512_IV, data, data_len, 64);
        std::memcpy(out, digest.data(), out_len);
        tinysha::secure_zero(digest.data(), digest.size());
        return 0;
    }
}
