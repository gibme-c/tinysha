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

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <tinysha.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2)
        return 0;

    // Byte 0: select algorithm (mod 6)
    // Byte 1: derive output_len (1..digest_size)
    // Remaining: data to hash
    static constexpr size_t digest_sizes[] = {32, 48, 64, 32, 48, 64};
    unsigned algo = data[0] % 6;
    size_t digest_size = digest_sizes[algo];
    size_t output_len = (static_cast<size_t>(data[1]) % digest_size) + 1;

    std::vector<uint8_t> input(data + 2, data + size);

    std::vector<uint8_t> full;
    std::vector<uint8_t> truncated;

    switch (algo)
    {
    case 0:
        full = tinysha::sha256(input);
        truncated = tinysha::sha256(input, output_len);
        break;
    case 1:
        full = tinysha::sha384(input);
        truncated = tinysha::sha384(input, output_len);
        break;
    case 2:
        full = tinysha::sha512(input);
        truncated = tinysha::sha512(input, output_len);
        break;
    case 3:
        full = tinysha::sha3_256(input);
        truncated = tinysha::sha3_256(input, output_len);
        break;
    case 4:
        full = tinysha::sha3_384(input);
        truncated = tinysha::sha3_384(input, output_len);
        break;
    case 5:
        full = tinysha::sha3_512(input);
        truncated = tinysha::sha3_512(input, output_len);
        break;
    }

    assert(truncated.size() == output_len);
    assert(std::vector<uint8_t>(full.begin(), full.begin() + static_cast<ptrdiff_t>(output_len)) == truncated);
    return 0;
}
