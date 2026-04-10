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

#include "tinysha/sha256.h"

#include "cpuid.h"
#include "internal/endian.h"
#include "tinysha/common.h"

#include <atomic>
#include <cstring>

namespace tinysha
{
    namespace internal
    {
        extern void sha256_compress_portable(uint32_t state[8], const uint8_t block[64]);
#if (defined(__x86_64__) || defined(_M_X64)) && !defined(TINYSHA_FORCE_PORTABLE)
        extern void sha256_compress_x64(uint32_t state[8], const uint8_t block[64]);
        extern void sha256_compress_bmi2(uint32_t state[8], const uint8_t block[64]);
        extern void sha256_compress_avx2(uint32_t state[8], const uint8_t block[64]);
        extern void sha256_compress_avx512(uint32_t state[8], const uint8_t block[64]);
#endif
#if (defined(__aarch64__) || defined(_M_ARM64)) && !defined(TINYSHA_FORCE_PORTABLE)
        extern void sha256_compress_arm_ce(uint32_t state[8], const uint8_t block[64]);
#endif
#if !defined(TINYSHA_FORCE_PORTABLE)
        extern CpuFeatures detect_cpu_features();
#endif
    } // namespace internal

    using compress_fn = void (*)(uint32_t state[8], const uint8_t block[64]);

    static compress_fn resolve_sha256_compress();
    static std::atomic<compress_fn> sha256_compress_impl {nullptr};

    static compress_fn get_sha256_compress()
    {
        auto fn = sha256_compress_impl.load(std::memory_order_acquire);
        if (fn)
            return fn;
        fn = resolve_sha256_compress();
        sha256_compress_impl.store(fn, std::memory_order_release);
        return fn;
    }

    static compress_fn resolve_sha256_compress()
    {
#if (defined(__x86_64__) || defined(_M_X64)) && !defined(TINYSHA_FORCE_PORTABLE)
        auto features = internal::detect_cpu_features();
        if (features.avx512f)
            return internal::sha256_compress_avx512;
        if (features.avx2 && features.bmi2)
            return internal::sha256_compress_avx2;
        if (features.bmi2)
            return internal::sha256_compress_bmi2;
        return internal::sha256_compress_x64;
#elif (defined(__aarch64__) || defined(_M_ARM64)) && !defined(TINYSHA_FORCE_PORTABLE)
        auto features = internal::detect_cpu_features();
        if (features.arm_sha256)
            return internal::sha256_compress_arm_ce;
        return internal::sha256_compress_portable;
#else
        return internal::sha256_compress_portable;
#endif
    }

    // SHA-256 initial hash values (FIPS 180-4)
    static constexpr uint32_t SHA256_IV[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    };

    static std::vector<uint8_t> sha256_impl(const uint8_t *data, size_t len)
    {
        auto compress = get_sha256_compress();

        uint32_t state[8];
        std::memcpy(state, SHA256_IV, sizeof(state));

        // Process complete blocks
        size_t offset = 0;
        while (offset + 64 <= len)
        {
            compress(state, data + offset);
            offset += 64;
        }

        // Padding
        uint8_t block[64];
        size_t remaining = len - offset;
        if (remaining > 0)
            std::memcpy(block, data + offset, remaining);
        block[remaining] = 0x80;
        remaining++;

        if (remaining > 56)
        {
            // Need two blocks for padding
            std::memset(block + remaining, 0, 64 - remaining);
            compress(state, block);
            std::memset(block, 0, 56);
        }
        else
        {
            std::memset(block + remaining, 0, 56 - remaining);
        }

        // Append big-endian bit length
        uint64_t bit_len = static_cast<uint64_t>(len) * 8;
        internal::store_be64(block + 56, bit_len);
        compress(state, block);

        // Produce output
        std::vector<uint8_t> digest(32);
        for (int i = 0; i < 8; ++i)
            internal::store_be32(digest.data() + i * 4, state[i]);

        secure_zero(state, sizeof(state));
        secure_zero(block, sizeof(block));

        return digest;
    }

    std::vector<uint8_t> sha256(const std::vector<uint8_t> &data)
    {
        return sha256_impl(data.data(), data.size());
    }

    std::vector<uint8_t> sha256(const std::vector<uint8_t> &data, size_t output_len)
    {
        auto full = sha256_impl(data.data(), data.size());
        if (output_len < full.size())
        {
            secure_zero(full.data() + output_len, full.size() - output_len);
            full.resize(output_len);
        }
        return full;
    }

    std::vector<uint8_t> SHA256Traits::hash(const std::vector<uint8_t> &data)
    {
        return sha256(data);
    }

} // namespace tinysha

extern "C"
{
    int tinysha_sha256(const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len)
    {
        if (!out || out_len == 0 || out_len > 32)
            return -1;
        if (!data && data_len > 0)
            return -1;
        auto digest = tinysha::sha256_impl(data, data_len);
        std::memcpy(out, digest.data(), out_len);
        tinysha::secure_zero(digest.data(), digest.size());
        return 0;
    }
}
