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

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <tinysha.h>
#include <vector>

// ---------------------------------------------------------------------------
// Cycle counter support
// ---------------------------------------------------------------------------
#if defined(__x86_64__) || defined(_M_X64)
#if defined(__GNUC__) || defined(__clang__)
#include <x86intrin.h>
#elif defined(_MSC_VER)
#include <intrin.h>
#endif
#define HAS_RDTSC 1
static inline uint64_t rdtsc_val()
{
    return __rdtsc();
}
#elif defined(__aarch64__)
#define HAS_RDTSC 1
static inline uint64_t rdtsc_val()
{
    uint64_t val;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(val));
    return val;
}
#endif

// ---------------------------------------------------------------------------
// Backend declarations (symbols are in libtinysha)
// ---------------------------------------------------------------------------
namespace tinysha::internal
{
    extern void sha256_compress_portable(uint32_t state[8], const uint8_t block[64]);
    extern void sha512_compress_portable(uint64_t state[8], const uint8_t block[128]);
    extern void keccak_f1600_portable(uint64_t state[25]);

#if (defined(__x86_64__) || defined(_M_X64)) && !defined(TINYSHA_FORCE_PORTABLE)
    extern void sha256_compress_x64(uint32_t state[8], const uint8_t block[64]);
    extern void sha256_compress_bmi2(uint32_t state[8], const uint8_t block[64]);
    extern void sha256_compress_avx2(uint32_t state[8], const uint8_t block[64]);
    extern void sha256_compress_avx512(uint32_t state[8], const uint8_t block[64]);

    extern void sha512_compress_x64(uint64_t state[8], const uint8_t block[128]);
    extern void sha512_compress_bmi2(uint64_t state[8], const uint8_t block[128]);
    extern void sha512_compress_avx2(uint64_t state[8], const uint8_t block[128]);
    extern void sha512_compress_avx512(uint64_t state[8], const uint8_t block[128]);

    extern void keccak_f1600_x64(uint64_t state[25]);
    extern void keccak_f1600_avx2(uint64_t state[25]);
    extern void keccak_f1600_avx512(uint64_t state[25]);
#endif

#if (defined(__aarch64__) || defined(_M_ARM64)) && !defined(TINYSHA_FORCE_PORTABLE)
    extern void sha256_compress_arm_ce(uint32_t state[8], const uint8_t block[64]);
    extern void sha512_compress_arm_ce(uint64_t state[8], const uint8_t block[128]);
    extern void keccak_f1600_arm_ce(uint64_t state[25]);
#endif
} // namespace tinysha::internal

#if !defined(TINYSHA_FORCE_PORTABLE) \
    && (defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64))
#include "cpuid.h"
#define HAS_SIMD_BACKENDS 1
#endif

// ---------------------------------------------------------------------------
// Timing helpers
// ---------------------------------------------------------------------------
struct BenchResult
{
    size_t iterations;
    double elapsed_sec;
    double total_bytes;
#ifdef HAS_RDTSC
    uint64_t tsc_start;
    uint64_t tsc_end;
#endif
};

static void print_result(const char *label, size_t data_size, const BenchResult &r)
{
    double mb_per_sec = (r.total_bytes / (1024.0 * 1024.0)) / r.elapsed_sec;
#ifdef HAS_RDTSC
    double cycles = static_cast<double>(r.tsc_end - r.tsc_start);
    double cpb = cycles / r.total_bytes;
    std::printf(
        "  %-20s  %8zuB  %10zu iters  %10.2f MB/s  %6.2f cpb\n", label, data_size, r.iterations, mb_per_sec, cpb);
#else
    std::printf("  %-20s  %8zuB  %10zu iters  %10.2f MB/s\n", label, data_size, r.iterations, mb_per_sec);
#endif
}

// ---------------------------------------------------------------------------
// Full-hash throughput benchmark
// ---------------------------------------------------------------------------
static void bench_hash(
    const char *name,
    std::vector<uint8_t> (*fn)(const std::vector<uint8_t> &),
    size_t data_size,
    double duration_sec = 0.5)
{
    std::vector<uint8_t> data(data_size, 0xAB);
    size_t iterations = 0;

#ifdef HAS_RDTSC
    uint64_t tsc0 = rdtsc_val();
#endif
    auto start = std::chrono::high_resolution_clock::now();
    double elapsed = 0.0;

    while (elapsed < duration_sec)
    {
        auto result = fn(data);
        (void)result;
        iterations++;
        auto now = std::chrono::high_resolution_clock::now();
        elapsed = std::chrono::duration<double>(now - start).count();
    }

#ifdef HAS_RDTSC
    uint64_t tsc1 = rdtsc_val();
#endif

    BenchResult r {};
    r.iterations = iterations;
    r.elapsed_sec = elapsed;
    r.total_bytes = static_cast<double>(data_size) * static_cast<double>(iterations);
#ifdef HAS_RDTSC
    r.tsc_start = tsc0;
    r.tsc_end = tsc1;
#endif
    print_result(name, data_size, r);
}

// ---------------------------------------------------------------------------
// Per-backend SHA-256 compress benchmark
// ---------------------------------------------------------------------------
using sha256_compress_fn = void (*)(uint32_t[8], const uint8_t[64]);

static void bench_sha256_compress(const char *name, sha256_compress_fn fn, double duration_sec = 1.0)
{
    static constexpr uint32_t IV[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    };
    uint32_t state[8];
    std::memcpy(state, IV, sizeof(state));
    uint8_t block[64] = {};

    size_t iterations = 0;
#ifdef HAS_RDTSC
    uint64_t tsc0 = rdtsc_val();
#endif
    auto start = std::chrono::high_resolution_clock::now();
    double elapsed = 0.0;

    while (elapsed < duration_sec)
    {
        for (int i = 0; i < 1024; ++i)
            fn(state, block);
        iterations += 1024;
        auto now = std::chrono::high_resolution_clock::now();
        elapsed = std::chrono::duration<double>(now - start).count();
    }

#ifdef HAS_RDTSC
    uint64_t tsc1 = rdtsc_val();
#endif

    BenchResult r {};
    r.iterations = iterations;
    r.elapsed_sec = elapsed;
    r.total_bytes = static_cast<double>(iterations) * 64.0;
#ifdef HAS_RDTSC
    r.tsc_start = tsc0;
    r.tsc_end = tsc1;
#endif
    print_result(name, 64, r);
}

// ---------------------------------------------------------------------------
// Per-backend SHA-512 compress benchmark
// ---------------------------------------------------------------------------
using sha512_compress_fn = void (*)(uint64_t[8], const uint8_t[128]);

static void bench_sha512_compress(const char *name, sha512_compress_fn fn, double duration_sec = 1.0)
{
    static constexpr uint64_t IV[8] = {
        0x6a09e667f3bcc908ULL,
        0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL,
        0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL,
        0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL,
        0x5be0cd19137e2179ULL,
    };
    uint64_t state[8];
    std::memcpy(state, IV, sizeof(state));
    uint8_t block[128] = {};

    size_t iterations = 0;
#ifdef HAS_RDTSC
    uint64_t tsc0 = rdtsc_val();
#endif
    auto start = std::chrono::high_resolution_clock::now();
    double elapsed = 0.0;

    while (elapsed < duration_sec)
    {
        for (int i = 0; i < 1024; ++i)
            fn(state, block);
        iterations += 1024;
        auto now = std::chrono::high_resolution_clock::now();
        elapsed = std::chrono::duration<double>(now - start).count();
    }

#ifdef HAS_RDTSC
    uint64_t tsc1 = rdtsc_val();
#endif

    BenchResult r {};
    r.iterations = iterations;
    r.elapsed_sec = elapsed;
    r.total_bytes = static_cast<double>(iterations) * 128.0;
#ifdef HAS_RDTSC
    r.tsc_start = tsc0;
    r.tsc_end = tsc1;
#endif
    print_result(name, 128, r);
}

// ---------------------------------------------------------------------------
// Per-backend Keccak permute benchmark
// ---------------------------------------------------------------------------
using keccak_fn = void (*)(uint64_t[25]);

static void bench_keccak_permute(const char *name, keccak_fn fn, size_t rate, double duration_sec = 1.0)
{
    uint64_t state[25] = {};
    size_t iterations = 0;
#ifdef HAS_RDTSC
    uint64_t tsc0 = rdtsc_val();
#endif
    auto start = std::chrono::high_resolution_clock::now();
    double elapsed = 0.0;

    while (elapsed < duration_sec)
    {
        for (int i = 0; i < 1024; ++i)
            fn(state);
        iterations += 1024;
        auto now = std::chrono::high_resolution_clock::now();
        elapsed = std::chrono::duration<double>(now - start).count();
    }

#ifdef HAS_RDTSC
    uint64_t tsc1 = rdtsc_val();
#endif

    BenchResult r {};
    r.iterations = iterations;
    r.elapsed_sec = elapsed;
    r.total_bytes = static_cast<double>(iterations) * static_cast<double>(rate);
#ifdef HAS_RDTSC
    r.tsc_start = tsc0;
    r.tsc_end = tsc1;
#endif
    print_result(name, rate, r);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main()
{
    static const size_t sizes[] = {64, 256, 1024, 4096, 65536, 1048576};

    struct HashBench
    {
        const char *name;
        std::vector<uint8_t> (*fn)(const std::vector<uint8_t> &);
    };

    HashBench hashes[] = {
        {"SHA-256", tinysha::sha256},
        {"SHA-384", tinysha::sha384},
        {"SHA-512", tinysha::sha512},
        {"SHA3-256", tinysha::sha3_256},
        {"SHA3-384", tinysha::sha3_384},
        {"SHA3-512", tinysha::sha3_512},
    };

    std::printf("TinySHA Benchmark\n");
    std::printf("=================\n\n");

    // ----- Full-hash throughput -----
    std::printf("--- Full-Hash Throughput (via dispatch) ---\n\n");
    for (const auto &h : hashes)
    {
        std::printf("%s:\n", h.name);
        for (size_t sz : sizes)
            bench_hash(h.name, h.fn, sz, 0.5);
        std::printf("\n");
    }

    // ----- HMAC -----
    std::printf("HMAC-SHA-256:\n");
    std::vector<uint8_t> key(32, 0xCC);
    for (size_t sz : sizes)
    {
        std::vector<uint8_t> data(sz, 0xAB);
        size_t iterations = 0;
#ifdef HAS_RDTSC
        uint64_t tsc0 = rdtsc_val();
#endif
        auto start = std::chrono::high_resolution_clock::now();
        double elapsed = 0.0;
        while (elapsed < 0.5)
        {
            auto result = tinysha::hmac<tinysha::SHA256Traits>(key, data);
            (void)result;
            iterations++;
            auto now = std::chrono::high_resolution_clock::now();
            elapsed = std::chrono::duration<double>(now - start).count();
        }
#ifdef HAS_RDTSC
        uint64_t tsc1 = rdtsc_val();
#endif
        BenchResult r {};
        r.iterations = iterations;
        r.elapsed_sec = elapsed;
        r.total_bytes = static_cast<double>(sz) * static_cast<double>(iterations);
#ifdef HAS_RDTSC
        r.tsc_start = tsc0;
        r.tsc_end = tsc1;
#endif
        print_result("HMAC-SHA-256", sz, r);
    }
    std::printf("\n");

    // ----- PBKDF2 -----
    std::printf("PBKDF2-SHA-256 (1000 iterations, 32B output):\n");
    {
        std::vector<uint8_t> pw = {0x70, 0x61, 0x73, 0x73};
        std::vector<uint8_t> salt = {0x73, 0x61, 0x6c, 0x74};
        size_t iterations = 0;
        auto start = std::chrono::high_resolution_clock::now();
        double elapsed = 0.0;
        while (elapsed < 2.0)
        {
            auto result = tinysha::pbkdf2<tinysha::SHA256Traits>(pw, salt, 1000, 32);
            (void)result;
            iterations++;
            auto now = std::chrono::high_resolution_clock::now();
            elapsed = std::chrono::duration<double>(now - start).count();
        }
        std::printf(
            "  %zu calls in %.2fs (%.1f calls/sec)\n", iterations, elapsed, static_cast<double>(iterations) / elapsed);
    }
    std::printf("\n");

    // ----- Per-backend compress/permute -----
    std::printf("--- Per-Backend Compress/Permute ---\n\n");

    std::printf("SHA-256 compress (per block = 64B):\n");
    bench_sha256_compress("portable", tinysha::internal::sha256_compress_portable);
#ifdef HAS_SIMD_BACKENDS
    {
        auto features = tinysha::internal::detect_cpu_features();
#if defined(__x86_64__) || defined(_M_X64)
        bench_sha256_compress("x64", tinysha::internal::sha256_compress_x64);
        if (features.bmi2)
            bench_sha256_compress("bmi2", tinysha::internal::sha256_compress_bmi2);
        if (features.avx2 && features.bmi2)
            bench_sha256_compress("avx2+bmi2", tinysha::internal::sha256_compress_avx2);
        if (features.avx512f)
            bench_sha256_compress("avx512", tinysha::internal::sha256_compress_avx512);
#endif
#if defined(__aarch64__) || defined(_M_ARM64)
        if (features.arm_sha256)
            bench_sha256_compress("arm-ce", tinysha::internal::sha256_compress_arm_ce);
#endif
    }
#endif
    std::printf("\n");

    std::printf("SHA-512 compress (per block = 128B):\n");
    bench_sha512_compress("portable", tinysha::internal::sha512_compress_portable);
#ifdef HAS_SIMD_BACKENDS
    {
        auto features = tinysha::internal::detect_cpu_features();
#if defined(__x86_64__) || defined(_M_X64)
        bench_sha512_compress("x64", tinysha::internal::sha512_compress_x64);
        if (features.bmi2)
            bench_sha512_compress("bmi2", tinysha::internal::sha512_compress_bmi2);
        if (features.avx2 && features.bmi2)
            bench_sha512_compress("avx2+bmi2", tinysha::internal::sha512_compress_avx2);
        if (features.avx512f)
            bench_sha512_compress("avx512", tinysha::internal::sha512_compress_avx512);
#endif
#if defined(__aarch64__) || defined(_M_ARM64)
        if (features.arm_sha512)
            bench_sha512_compress("arm-ce", tinysha::internal::sha512_compress_arm_ce);
#endif
    }
#endif
    std::printf("\n");

    std::printf("Keccak-f[1600] permute (rate=136 for SHA3-256):\n");
    bench_keccak_permute("portable", tinysha::internal::keccak_f1600_portable, 136);
#ifdef HAS_SIMD_BACKENDS
    {
        auto features = tinysha::internal::detect_cpu_features();
#if defined(__x86_64__) || defined(_M_X64)
        bench_keccak_permute("x64", tinysha::internal::keccak_f1600_x64, 136);
        if (features.avx2)
            bench_keccak_permute("avx2", tinysha::internal::keccak_f1600_avx2, 136);
        if (features.avx512f)
            bench_keccak_permute("avx512", tinysha::internal::keccak_f1600_avx512, 136);
#endif
#if defined(__aarch64__) || defined(_M_ARM64)
        if (features.arm_sha3)
            bench_keccak_permute("arm-ce", tinysha::internal::keccak_f1600_arm_ce, 136);
#endif
    }
#endif
    std::printf("\n");

    return 0;
}
