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

#include "../cpuid.h"
#include "endian.h"
#include "tinysha/common.h"

#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <vector>

namespace tinysha
{
    namespace internal
    {

        extern void keccak_f1600_portable(uint64_t state[25]);
#if (defined(__x86_64__) || defined(_M_X64)) && !defined(TINYSHA_FORCE_PORTABLE)
        extern void keccak_f1600_x64(uint64_t state[25]);
        extern void keccak_f1600_avx2(uint64_t state[25]);
        extern void keccak_f1600_avx512(uint64_t state[25]);
#endif
#if (defined(__aarch64__) || defined(_M_ARM64)) && !defined(TINYSHA_FORCE_PORTABLE)
        extern void keccak_f1600_arm_ce(uint64_t state[25]);
#endif

        using keccak_fn = void (*)(uint64_t state[25]);

        inline keccak_fn resolve_keccak()
        {
#if (defined(__x86_64__) || defined(_M_X64)) && !defined(TINYSHA_FORCE_PORTABLE)
            auto features = detect_cpu_features();
            if (features.avx512f)
                return keccak_f1600_avx512;
            if (features.avx2)
                return keccak_f1600_avx2;
            return keccak_f1600_x64;
#elif (defined(__aarch64__) || defined(_M_ARM64)) && !defined(TINYSHA_FORCE_PORTABLE)
            auto features = detect_cpu_features();
            if (features.arm_sha3)
                return keccak_f1600_arm_ce;
            return keccak_f1600_portable;
#else
            return keccak_f1600_portable;
#endif
        }

        inline keccak_fn get_keccak()
        {
            static std::atomic<keccak_fn> impl {nullptr};
            auto fn = impl.load(std::memory_order_acquire);
            if (fn)
                return fn;
            fn = resolve_keccak();
            impl.store(fn, std::memory_order_release);
            return fn;
        }

        inline std::vector<uint8_t> sha3_sponge(const uint8_t *data, size_t len, size_t rate_bytes, size_t digest_bytes)
        {
            assert(rate_bytes > 0 && rate_bytes <= 200 && rate_bytes % 8 == 0);

            auto permute = get_keccak();

            uint64_t state[25] = {};
            size_t offset = 0;

            // Absorb: XOR input into state, rate bytes at a time
            while (offset + rate_bytes <= len)
            {
                for (size_t i = 0; i < rate_bytes / 8; ++i)
                    state[i] ^= load_le64(data + offset + i * 8);
                permute(state);
                offset += rate_bytes;
            }

            // Final block: pad
            size_t remaining = len - offset;
            uint8_t block[200] = {};
            std::memcpy(block, data + offset, remaining);

            // SHA-3 domain separator: 0x06, final padding bit: 0x80
            block[remaining] = 0x06;
            block[rate_bytes - 1] |= 0x80;

            for (size_t i = 0; i < rate_bytes / 8; ++i)
                state[i] ^= load_le64(block + i * 8);
            permute(state);

            // Squeeze
            std::vector<uint8_t> digest(digest_bytes);
            size_t squeezed = 0;
            while (squeezed < digest_bytes)
            {
                size_t to_copy = digest_bytes - squeezed;
                if (to_copy > rate_bytes)
                    to_copy = rate_bytes;

                size_t full_lanes = to_copy / 8;
                for (size_t i = 0; i < full_lanes; ++i)
                    store_le64(digest.data() + squeezed + i * 8, state[i]);
                if (to_copy % 8 != 0)
                {
                    uint8_t tmp[8];
                    store_le64(tmp, state[full_lanes]);
                    std::memcpy(digest.data() + squeezed + full_lanes * 8, tmp, to_copy % 8);
                }

                squeezed += to_copy;
                if (squeezed < digest_bytes)
                    permute(state);
            }

            secure_zero(state, sizeof(state));
            secure_zero(block, sizeof(block));

            return digest;
        }

    } // namespace internal
} // namespace tinysha
