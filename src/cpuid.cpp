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

#include "cpuid.h"

#if defined(__x86_64__) || defined(_M_X64)
#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>
#endif
#endif

#if defined(__aarch64__) && defined(__linux__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif

namespace tinysha
{
    namespace internal
    {

#if defined(__x86_64__) || defined(_M_X64)

        static void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t &eax, uint32_t &ebx, uint32_t &ecx, uint32_t &edx)
        {
#if defined(_MSC_VER) && !defined(__clang__)
            int regs[4];
            __cpuidex(regs, static_cast<int>(leaf), static_cast<int>(subleaf));
            eax = static_cast<uint32_t>(regs[0]);
            ebx = static_cast<uint32_t>(regs[1]);
            ecx = static_cast<uint32_t>(regs[2]);
            edx = static_cast<uint32_t>(regs[3]);
#else
            __asm__ __volatile__("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(leaf), "c"(subleaf));
#endif
        }

        static uint64_t xgetbv(uint32_t xcr)
        {
#if defined(_MSC_VER) && !defined(__clang__)
            return _xgetbv(xcr);
#else
            uint32_t eax, edx;
            __asm__ __volatile__("xgetbv" : "=a"(eax), "=d"(edx) : "c"(xcr));
            return static_cast<uint64_t>(edx) << 32 | eax;
#endif
        }

        CpuFeatures detect_cpu_features()
        {
            CpuFeatures f;
            uint32_t eax, ebx, ecx, edx;

            // Check max leaf
            cpuid(0, 0, eax, ebx, ecx, edx);
            uint32_t max_leaf = eax;
            if (max_leaf < 7)
                return f;

            // Leaf 1: check OSXSAVE (ECX bit 27) — required before XGETBV
            cpuid(1, 0, eax, ebx, ecx, edx);
            bool osxsave = (ecx & (1u << 27)) != 0;
            if (!osxsave)
                return f;

            // Read XCR0 to check OS-enabled state saving
            uint64_t xcr0 = xgetbv(0);
            bool os_avx = (xcr0 & 0x06) == 0x06; // bits 1+2: SSE + AVX state
            bool os_avx512 = os_avx && (xcr0 & 0xE0) == 0xE0; // bits 5+6+7: opmask + ZMM hi256 + ZMM hi16

            // Leaf 7, subleaf 0
            cpuid(7, 0, eax, ebx, ecx, edx);
            f.avx2 = os_avx && (ebx & (1u << 5)) != 0;
            f.bmi2 = (ebx & (1u << 8)) != 0;
            f.adx = (ebx & (1u << 19)) != 0;
            f.avx512f = os_avx512 && (ebx & (1u << 16)) != 0;
            f.avx512ifma = os_avx512 && (ebx & (1u << 21)) != 0;

            return f;
        }

#elif defined(__aarch64__) || defined(_M_ARM64)

        CpuFeatures detect_cpu_features()
        {
            CpuFeatures f;

#if defined(__APPLE__)
            // Apple Silicon (M1+) always has SHA-256, SHA-512, and SHA-3 extensions
            f.arm_sha256 = true;
            f.arm_sha512 = true;
            f.arm_sha3 = true;
#elif defined(__linux__)
            unsigned long hwcap = getauxval(AT_HWCAP);
            f.arm_sha256 = (hwcap & HWCAP_SHA2) != 0;
#if defined(HWCAP_SHA512)
            f.arm_sha512 = (hwcap & HWCAP_SHA512) != 0;
#endif
#if defined(HWCAP_SHA3)
            f.arm_sha3 = (hwcap & HWCAP_SHA3) != 0;
#endif
#elif defined(_M_ARM64)
            // Windows on ARM64: SHA-256 CE is baseline on all Windows ARM64 devices
            f.arm_sha256 = true;
            // SHA-512 and SHA-3 detection not exposed via standard Windows API;
            // default to portable fallback to avoid illegal instruction faults
            f.arm_sha512 = false;
            f.arm_sha3 = false;
#endif

            return f;
        }

#else

        // Non-x86, non-ARM64: no SIMD features
        CpuFeatures detect_cpu_features()
        {
            return CpuFeatures {};
        }

#endif

    } // namespace internal
} // namespace tinysha
