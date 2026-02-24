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

#include "tinysha/sha3_384.h"

#include "internal/keccak_sponge.h"

#include <cstring>

namespace tinysha
{

    std::vector<uint8_t> sha3_384(const std::vector<uint8_t> &data)
    {
        return internal::sha3_sponge(data.data(), data.size(), 104, 48);
    }

    std::vector<uint8_t> sha3_384(const std::vector<uint8_t> &data, size_t output_len)
    {
        auto full = internal::sha3_sponge(data.data(), data.size(), 104, 48);
        if (output_len < full.size())
        {
            secure_zero(full.data() + output_len, full.size() - output_len);
            full.resize(output_len);
        }
        return full;
    }

    std::vector<uint8_t> SHA3_384Traits::hash(const std::vector<uint8_t> &data)
    {
        return sha3_384(data);
    }

} // namespace tinysha

extern "C"
{
    int tinysha_sha3_384(const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len)
    {
        if (!out || out_len == 0 || out_len > 48)
            return -1;
        if (!data && data_len > 0)
            return -1;
        auto digest = tinysha::internal::sha3_sponge(data, data_len, 104, 48);
        std::memcpy(out, digest.data(), out_len);
        tinysha::secure_zero(digest.data(), digest.size());
        return 0;
    }
}
