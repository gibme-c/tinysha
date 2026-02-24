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

#include "tinysha/common.h"

#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace tinysha
{

#if defined(_WIN32)

    void secure_zero(void *ptr, size_t len)
    {
        SecureZeroMemory(ptr, len);
    }

#elif defined(__STDC_LIB_EXT1__)

    void secure_zero(void *ptr, size_t len)
    {
        memset_s(ptr, len, 0, len);
    }

#else

    // Use a volatile function pointer to prevent dead-store elimination
    static void *(*const volatile memset_ptr)(void *, int, size_t) = std::memset;

    void secure_zero(void *ptr, size_t len)
    {
        memset_ptr(ptr, 0, len);
    }

#endif

    bool constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len)
    {
        volatile uint8_t diff = 0;
        for (size_t i = 0; i < len; ++i)
        {
            diff |= static_cast<uint8_t>(a[i] ^ b[i]);
        }
        // Use volatile for the final comparison to prevent the compiler from
        // optimizing the loop body away or short-circuiting the result.
        volatile uint8_t result = static_cast<uint8_t>(diff == 0);
        return result != 0;
    }

} // namespace tinysha

extern "C" int tinysha_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    return tinysha::constant_time_equal(a, b, len) ? 1 : 0;
}
