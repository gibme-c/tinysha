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

#include <cstddef>
#include <cstdint>
#include <vector>

// Symbol visibility for shared library builds
#if defined(TINYSHA_SHARED)
#if defined(_WIN32) || defined(__CYGWIN__)
#if defined(TINYSHA_BUILDING)
#define TINYSHA_EXPORT __declspec(dllexport)
#else
#define TINYSHA_EXPORT __declspec(dllimport)
#endif
#elif defined(__GNUC__) || defined(__clang__)
#define TINYSHA_EXPORT __attribute__((visibility("default")))
#else
#define TINYSHA_EXPORT
#endif
#else
#define TINYSHA_EXPORT
#endif

#ifdef __cplusplus
extern "C"
{
#endif

    TINYSHA_EXPORT int tinysha_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len);

#ifdef __cplusplus
}
#endif

namespace tinysha
{

    void secure_zero(void *ptr, size_t len);

    /// Constant-time comparison of two byte sequences.
    /// Returns true if all bytes are equal; false otherwise.
    /// Runs in time proportional to len regardless of where bytes differ.
    bool constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len);

    // Note: the early return on mismatched sizes is intentional and does not
    // constitute a timing side-channel. Callers always know the expected
    // digest length, so the size comparison reveals no secret information.
    inline bool constant_time_equal(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b)
    {
        if (a.size() != b.size())
            return false;
        return constant_time_equal(a.data(), b.data(), a.size());
    }

    template<typename HashTraits> struct hash_traits_info
    {
        static constexpr size_t digest_size = HashTraits::digest_size;
        static constexpr size_t block_size = HashTraits::block_size;
    };

} // namespace tinysha
