# TinySHA

[![CI Build Tests](https://github.com/gibme-c/tinysha/actions/workflows/ci.yml/badge.svg)](https://github.com/gibme-c/tinysha/actions/workflows/ci.yml)

A zero-dependency C++17 library for cryptographic hash functions, with SIMD-accelerated backends and runtime CPU dispatch.

TinySHA implements SHA-2 (SHA-256, SHA-384, SHA-512), SHA-3 (SHA3-256, SHA3-384, SHA3-512), HMAC, and PBKDF2. Each algorithm has a portable backend that compiles everywhere plus platform-specific backends (AVX2, AVX-512, BMI2, ARM Crypto Extensions) that are selected automatically at runtime based on detected CPU features. All intermediate key material is securely zeroed using platform-specific mechanisms the compiler can't optimize away.

Both a C++ template API and a plain C API (`extern "C"`) are provided. The C++ API returns `std::vector<uint8_t>` and uses traits-based templates for HMAC/PBKDF2. The C API uses caller-provided buffers and returns `int` (0 on success, -1 on error) with full input validation.

## Features

### Hash Functions

| Algorithm | Digest Size | Block Size | Standard |
|-----------|-------------|------------|----------|
| SHA-256 | 32 bytes | 64 bytes | FIPS 180-4 |
| SHA-384 | 48 bytes | 128 bytes | FIPS 180-4 |
| SHA-512 | 64 bytes | 128 bytes | FIPS 180-4 |
| SHA3-256 | 32 bytes | 136 bytes (rate) | FIPS 202 |
| SHA3-384 | 48 bytes | 104 bytes (rate) | FIPS 202 |
| SHA3-512 | 64 bytes | 72 bytes (rate) | FIPS 202 |

All hash functions support variable-length output truncation.

### HMAC and PBKDF2

HMAC and PBKDF2 are implemented as C++ templates parameterized on a `HashTraits` struct. Each hash algorithm provides its own traits type (`SHA256Traits`, `SHA512Traits`, `SHA3_256Traits`, etc.) with `digest_size`, `block_size`, and a static `hash()` method. The C API provides explicit instantiations for all six hash functions.

### SIMD Backends

Backend availability by platform:

| Algorithm | Portable | x64 | BMI2 | AVX2 | AVX-512 | ARM CE |
|-----------|----------|-----|------|------|---------|--------|
| SHA-256 | yes | yes | yes | yes | yes | yes |
| SHA-384 | yes | yes | yes | yes | yes | yes |
| SHA-512 | yes | yes | yes | yes | yes | yes |
| SHA3-256 | yes | yes | — | yes | yes | yes |
| SHA3-384 | yes | yes | — | yes | yes | yes |
| SHA3-512 | yes | yes | — | yes | yes | yes |

SHA-384 shares the SHA-512 compression function (same 80-round algorithm, different IVs, truncated output).

### Security

- **Secure memory erasure** — all intermediate state (hash state, HMAC keys, PBKDF2 intermediates) is zeroed via `secure_zero()`, which uses `SecureZeroMemory` (Windows), `memset_s` (C11), or a volatile function pointer to prevent dead-store elimination
- **Constant-time comparison** — `constant_time_equal()` for digest verification, with volatile accumulator to prevent short-circuit optimization
- **Input validation** — all C API functions validate pointers, lengths, and bounds before any computation; NULL inputs with non-zero length return -1
- **Build hardening** — stack protectors, control flow integrity, ASLR, DEP, RELRO, and symbol visibility hiding across GCC, Clang, MSVC, and MinGW

## Building

Requires CMake 3.10+ and a C++17 compiler.

```bash
# Configure and build
cmake -S . -B build -DTINYSHA_BUILD_TESTS=ON
cmake --build build --config Release -j

# Run tests
./build/tinysha_tests          # Linux / macOS / MinGW
./build/Release/tinysha_tests  # Windows (MSVC)
```

### CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `TINYSHA_BUILD_TESTS` | `ON` top-level, `OFF` as subdirectory | Build the unit test executable (`tinysha_tests`) |
| `TINYSHA_BUILD_BENCHMARKS` | `ON` top-level, `OFF` as subdirectory | Build the benchmark tool (`tinysha_benchmarks`) |
| `TINYSHA_BUILD_FUZZERS` | `ON` top-level, `OFF` as subdirectory | Build libFuzzer targets (Clang + Linux only) |
| `BUILD_SHARED_LIBS` | `OFF` | Build as a shared library (`.so`/`.dll`/`.dylib`) |
| `TINYSHA_FORCE_PORTABLE` | `OFF` | Disable all SIMD backends; use only portable C++ code |
| `CMAKE_BUILD_TYPE` | `Release` | `Debug`, `Release`, or `RelWithDebInfo` |

## Usage

Include the umbrella header for everything:

```cpp
#include <tinysha/tinysha.h>
```

Or include individual headers:

```cpp
#include <tinysha/sha256.h>
#include <tinysha/hmac.h>
#include <tinysha/pbkdf2.h>
```

Link against the `tinysha` library target in your CMake project:

```cmake
add_subdirectory(tinysha)
target_link_libraries(your_target tinysha)
```

### C++ API

```cpp
#include <tinysha/tinysha.h>

// Hash
std::vector<uint8_t> data = { /* ... */ };
auto digest = tinysha::sha256(data);
auto short_digest = tinysha::sha256(data, 16);  // truncated to 16 bytes

// HMAC
auto mac = tinysha::hmac<tinysha::SHA256Traits>(key, data);
auto mac_trunc = tinysha::hmac<tinysha::SHA256Traits>(key, data, 16);

// PBKDF2
auto derived = tinysha::pbkdf2<tinysha::SHA256Traits>(password, salt, 100000, 32);

// Constant-time digest comparison
bool match = tinysha::constant_time_equal(digest_a, digest_b);
```

SHA-3 works the same way:

```cpp
auto digest = tinysha::sha3_256(data);
auto mac = tinysha::hmac<tinysha::SHA3_256Traits>(key, data);
auto derived = tinysha::pbkdf2<tinysha::SHA3_512Traits>(password, salt, 100000, 64);
```

### C API

All C functions return 0 on success, -1 on error (NULL pointers, invalid lengths, etc.).

```c
#include <tinysha/sha256.h>
#include <tinysha/hmac.h>
#include <tinysha/pbkdf2.h>

uint8_t digest[32];
tinysha_sha256(data, data_len, digest, 32);

uint8_t mac[32];
tinysha_hmac_sha256(key, key_len, data, data_len, mac, 32);

uint8_t derived[32];
tinysha_pbkdf2_sha256(pw, pw_len, salt, salt_len, 100000, derived, 32);

/* Constant-time comparison */
int equal = tinysha_constant_time_equal(digest_a, digest_b, 32);
```

## Architecture

### Dispatch

Each hash function uses `std::atomic<fn_ptr>` with acquire/release ordering for lazy runtime dispatch. On the first call, CPUID (x86) or `getauxval`/hardcoded detection (ARM) selects the best available backend. The function pointer is stored atomically — no mutexes, no `std::call_once`. Redundant resolution under contention is harmless by design.

Dispatch priority on x86_64:

- **SHA-256**: AVX-512F > AVX2+BMI2 > BMI2 > x64 baseline
- **SHA-512**: AVX-512F > AVX2+BMI2 > BMI2 > x64 baseline
- **Keccak** (SHA-3): AVX-512F > AVX2 > x64 baseline

Dispatch priority on ARM64:

- **SHA-256**: ARM SHA-256 CE > portable
- **SHA-512**: ARM SHA-512 CE > portable
- **Keccak** (SHA-3): ARM SHA-3 CE > portable

All other platforms use the portable backend unconditionally.

### SHA-2 Internals

SHA-256 uses 32-bit state with 64-round compression over 64-byte blocks. SHA-512 uses 64-bit state with 80-round compression over 128-byte blocks. SHA-384 is SHA-512 with different initial hash values and output truncated to 48 bytes — they share the same compression function.

Big-endian byte order throughout: message words loaded big-endian, bit-length appended big-endian.

Backend implementations:

- **Portable** — reference C++ with `rotr32`/`rotr64` helper functions
- **x64** — unrolled rounds with compiler-friendly register usage
- **BMI2** — constant-latency rotations via `RORX` (`_rorx_u32`/`_rorx_u64`)
- **AVX2** — 256-bit byte-swap for message loading; scalar round function
- **AVX-512** — `VPRORD` (SHA-256) and `VPRORQ` (SHA-512) for constant-time rotations; 256-bit byte-swap for message loading
- **ARM CE** — hardware SHA-256 instructions (`vsha256hq_u32`, `vsha256su0q_u32`, etc.) and SHA-512 instructions (`vsha512hq_u64`, `vsha512su0q_u64`, etc.)

### SHA-3 / Keccak Internals

All SHA-3 variants use a single Keccak-f[1600] permutation parameterized by rate: SHA3-256 (rate=136), SHA3-384 (rate=104), SHA3-512 (rate=72). The sponge construction absorbs input XORed into the state in rate-sized blocks, applies the `0x06` domain separator and `0x80` final padding, then squeezes output.

Little-endian byte order: state lanes loaded/stored as little-endian `uint64_t`.

Backend implementations:

- **Portable** — reference C++ with explicit theta/rho/pi/chi/iota steps
- **x64** — fully unrolled rho+pi, row-unrolled chi, pre-computed column parities for theta
- **AVX2** — vectorized theta step, optimized rho+pi/chi scheduling
- **AVX-512** — `VPTERNLOGQ` for single-instruction chi (`a ^ (~b & c)`), 512-bit XOR for theta
- **ARM CE** — `EOR3` (3-input XOR), `RAX1` (rotate-and-XOR), `XAR` (XOR-and-rotate), `BCAX` (bit-clear-and-XOR) from the ARMv8.2 SHA-3 extension

### HMAC / PBKDF2

Both are C++ templates parameterized on `HashTraits`. HMAC follows RFC 2104: derive a block-sized key, XOR with `ipad`/`opad`, hash inner then outer. PBKDF2 follows RFC 2898: iterative HMAC with counter blocks, XOR accumulation across iterations.

All intermediate buffers — key blocks, ipad, opad, HMAC intermediates, PBKDF2 U-values — are securely zeroed after use.

## Testing

Build with `-DTINYSHA_BUILD_TESTS=ON` to get the `tinysha_tests` executable. The test suite covers:

- **Known-answer tests** — NIST test vectors for all six hash algorithms (empty string, short messages, standard reference inputs)
- **HMAC test vectors** — RFC 4231 vectors for HMAC-SHA-256/384/512, plus SHA-3 HMAC vectors
- **PBKDF2 test vectors** — RFC 6070 vectors for PBKDF2-SHA-256, plus SHA-3 PBKDF2 vectors
- **Truncation tests** — verify truncated output matches the prefix of the full digest
- **CPUID tests** — verify CPU feature detection runs without crashing

The test harness is a custom header-only framework (`test_harness.h`) with `TEST`/`ASSERT_EQ` macros — no external test dependencies.

## Benchmarking

Build with `-DTINYSHA_BUILD_BENCHMARKS=ON` to get the `tinysha_benchmarks` executable. This benchmarks each hash, HMAC, and PBKDF2 variant, plus individual backend compression functions where dispatch allows direct access.

## Fuzzing

Fuzz targets are built automatically when using Clang on non-Windows platforms:

```bash
cmake -S . -B build-fuzz -DCMAKE_CXX_COMPILER=clang++
cmake --build build-fuzz
./build-fuzz/fuzz_sha256 corpus/sha256/
```

Eight fuzz targets cover SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, HMAC, and PBKDF2. Each links with `-fsanitize=fuzzer,address`.

## CI

GitHub Actions runs on every push, pull request, weekly schedule, and release. Every compiler is tested in both portable and native/SIMD configurations:

| Platform | Compilers | Configs |
|----------|-----------|---------|
| Linux x86_64 | GCC 11, GCC 12, Clang 14, Clang 15 | portable, native |
| Linux ARM64 | GCC, Clang | portable, arm64 |
| macOS ARM64 | AppleClang, Homebrew Clang | portable, arm64 |
| Windows x86_64 | MSVC, MinGW GCC | portable, native |

Unit tests and benchmarks run for every combination.

## License

BSD-3-Clause. See [LICENSE](LICENSE) for the full text.
