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

#include "tinysha/sha384.h"

#include "tinysha/common.h"

#include <cstring>

namespace tinysha
{

    // SHA-384 uses the SHA-512 engine with different IVs
    extern std::vector<uint8_t>
        sha512_engine(const uint64_t iv[8], const uint8_t *data, size_t len, size_t digest_bytes);

    // SHA-384 initial hash values (FIPS 180-4)
    static constexpr uint64_t SHA384_IV[8] = {
        0xcbbb9d5dc1059ed8ULL,
        0x629a292a367cd507ULL,
        0x9159015a3070dd17ULL,
        0x152fecd8f70e5939ULL,
        0x67332667ffc00b31ULL,
        0x8eb44a8768581511ULL,
        0xdb0c2e0d64f98fa7ULL,
        0x47b5481dbefa4fa4ULL,
    };

    std::vector<uint8_t> sha384(const std::vector<uint8_t> &data)
    {
        return sha512_engine(SHA384_IV, data.data(), data.size(), 48);
    }

    std::vector<uint8_t> sha384(const std::vector<uint8_t> &data, size_t output_len)
    {
        auto full = sha512_engine(SHA384_IV, data.data(), data.size(), 48);
        if (output_len < full.size())
        {
            secure_zero(full.data() + output_len, full.size() - output_len);
            full.resize(output_len);
        }
        return full;
    }

    std::vector<uint8_t> SHA384Traits::hash(const std::vector<uint8_t> &data)
    {
        return sha384(data);
    }

} // namespace tinysha

extern "C"
{
    int tinysha_sha384(const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len)
    {
        if (!out || out_len == 0 || out_len > 48)
            return -1;
        if (!data && data_len > 0)
            return -1;
        auto digest = tinysha::sha512_engine(tinysha::SHA384_IV, data, data_len, 48);
        std::memcpy(out, digest.data(), out_len);
        tinysha::secure_zero(digest.data(), digest.size());
        return 0;
    }
}
