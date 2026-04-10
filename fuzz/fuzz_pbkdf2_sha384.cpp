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

#include "portable_hash.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <tinysha.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 6)
        return 0;
    size_t pw_len = static_cast<size_t>(data[0]) % (size - 5);
    if (pw_len == 0)
        pw_len = 1;
    uint32_t iters = static_cast<uint32_t>(data[1]) | (static_cast<uint32_t>(data[2]) << 8);
    iters = (iters % 10) + 1;
    std::vector<uint8_t> pw(data + 5, data + 5 + pw_len);
    std::vector<uint8_t> salt(data + 5 + pw_len, data + size);
    if (salt.empty())
        salt.push_back(0);

    auto dispatch_result = tinysha::pbkdf2<tinysha::SHA384Traits>(pw, salt, iters, 48);
    auto portable_result = tinysha::pbkdf2<portable::SHA384Traits>(pw, salt, iters, 48);
    assert(dispatch_result == portable_result);
    return 0;
}
