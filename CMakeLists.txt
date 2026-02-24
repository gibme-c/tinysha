cmake_minimum_required(VERSION 3.10)
project(tinysha VERSION 0.1.0 LANGUAGES CXX)

include(CheckCXXCompilerFlag)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(BUILD_SHARED_LIBS "Build shared library" OFF)
option(BUILD_TESTS "Build unit tests" OFF)
option(BUILD_BENCHMARKS "Build benchmarks" OFF)
option(FORCE_PORTABLE "Disable SIMD backends; use only portable code" OFF)

# --- Library sources ---
set(TINYSHA_SOURCES
    src/sha256.cpp
    src/sha384.cpp
    src/sha512.cpp
    src/sha3_256.cpp
    src/sha3_384.cpp
    src/sha3_512.cpp
    src/hmac.cpp
    src/pbkdf2.cpp
    src/cpuid.cpp
    src/secure_zero.cpp
    src/backend/sha2_portable.cpp
    src/backend/keccak_portable.cpp
)

# Conditionally add SIMD backend sources on x86_64
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64" AND NOT FORCE_PORTABLE)
    list(APPEND TINYSHA_SOURCES
        src/backend/sha2_x64.cpp
        src/backend/sha2_avx2.cpp
        src/backend/sha2_avx512.cpp
        src/backend/sha2_bmi2_adx.cpp
        src/backend/keccak_x64.cpp
        src/backend/keccak_avx2.cpp
        src/backend/keccak_avx512.cpp
    )
endif()

# Conditionally add ARM64 crypto extension backend sources
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64" AND NOT FORCE_PORTABLE)
    list(APPEND TINYSHA_SOURCES
        src/backend/sha2_arm_ce.cpp
        src/backend/keccak_arm_ce.cpp
    )
endif()

add_library(tinysha ${TINYSHA_SOURCES})

# --- Shared library symbol visibility ---
if(BUILD_SHARED_LIBS)
    set_target_properties(tinysha PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
    )
    target_compile_definitions(tinysha PUBLIC TINYSHA_SHARED=1)
    target_compile_definitions(tinysha PRIVATE TINYSHA_BUILDING=1)
endif()

if(FORCE_PORTABLE)
    target_compile_definitions(tinysha PUBLIC TINYSHA_FORCE_PORTABLE=1)
endif()

target_include_directories(tinysha PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
# Internal headers (src/) for the library itself
target_include_directories(tinysha PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

set_target_properties(tinysha PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

# --- Detect MinGW environment ---
# Only use CMake's built-in MINGW (set for GCC with MinGW). Clang on Windows can
# target either MinGW or MSVC ABI, and the linker varies (GNU ld vs lld-link) —
# applying the wrong linker flags breaks the build. We let Clang on Windows rely
# on the OS defaults for DEP/ASLR (enabled by default on modern Windows) rather
# than guessing the linker style.

# --- Hardening flags ---
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(tinysha PRIVATE
        -Wall -Wextra -Wpedantic -Werror
        -Wconversion -Wsign-conversion -Wshadow
        -Wcast-align -Wundef
        -Wformat=2 -Wformat-security
        -fno-strict-overflow
    )
    # Stack protector: requires libssp or compiler-rt at link time.
    # Probe with try_compile to catch Clang+MinGW toolchains that lack libssp.
    include(CheckCXXSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-fstack-protector-strong")
    check_cxx_source_compiles("int main() { char buf[64]; buf[0] = 0; return buf[0]; }" HAS_STACK_PROTECTOR_STRONG)
    unset(CMAKE_REQUIRED_FLAGS)
    if(HAS_STACK_PROTECTOR_STRONG)
        target_compile_options(tinysha PRIVATE -fstack-protector-strong)
    endif()
    # -fPIC is implied on Windows PE; only needed on ELF/Mach-O
    if(NOT WIN32)
        target_compile_options(tinysha PRIVATE -fPIC)
        # Stack clash protection (Linux only — not supported on macOS/Apple Clang)
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            target_compile_options(tinysha PRIVATE -fstack-clash-protection)
        endif()
    endif()
    # Intel CET control flow integrity (x86_64 only)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
        check_cxx_compiler_flag("-fcf-protection=full" HAS_CF_PROTECTION)
        if(HAS_CF_PROTECTION)
            target_compile_options(tinysha PRIVATE -fcf-protection=full)
        endif()
    endif()
    # -Wstrict-aliasing=2 only for GCC (Clang doesn't support the =2 level)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(tinysha PRIVATE -Wstrict-aliasing=2)
        # libstdc++ container assertions in Debug (bounds checks on operator[], etc.)
        target_compile_options(tinysha PRIVATE
            $<$<CONFIG:Debug>:-D_GLIBCXX_ASSERTIONS>
        )
    endif()
    # _FORTIFY_SOURCE requires optimization; not reliably supported on MinGW
    if(NOT WIN32)
        target_compile_options(tinysha PRIVATE
            $<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=2>
        )
    endif()
    # Linker hardening (use LINK_FLAGS for CMake 3.10 compat)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set_property(TARGET tinysha APPEND_STRING PROPERTY LINK_FLAGS
            " -Wl,-z,relro,-z,now -Wl,-z,noexecstack")
        # Reject undefined symbols in shared libs (catches missing TINYSHA_EXPORT)
        if(BUILD_SHARED_LIBS)
            set_property(TARGET tinysha APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-z,defs")
        endif()
    endif()
    # macOS: -bind_at_load is deprecated on modern macOS (eager binding is the default)
    # MinGW linker hardening (DEP + ASLR) — only for GCC+MinGW (known GNU ld)
    if(MINGW)
        set_property(TARGET tinysha APPEND_STRING PROPERTY LINK_FLAGS
            " -Wl,--nxcompat -Wl,--dynamicbase -Wl,--high-entropy-va")
    endif()
elseif(MSVC)
    target_compile_options(tinysha PRIVATE
        /W4 /WX
        /sdl
        /GS
        /guard:cf
    )
    check_cxx_compiler_flag("/Qspectre" HAS_QSPECTRE)
    if(HAS_QSPECTRE)
        target_compile_options(tinysha PRIVATE /Qspectre)
    endif()
    set_property(TARGET tinysha APPEND_STRING PROPERTY LINK_FLAGS
        " /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA")
    # CET shadow stack compatibility
    check_cxx_compiler_flag("/guard:ehcont" HAS_GUARD_EHCONT)
    if(HAS_GUARD_EHCONT)
        target_compile_options(tinysha PRIVATE /guard:ehcont)
        set_property(TARGET tinysha APPEND_STRING PROPERTY LINK_FLAGS " /guard:ehcont /CETCOMPAT")
    endif()
endif()

# --- Per-backend SIMD compile flags ---
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64" AND NOT FORCE_PORTABLE)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        set_source_files_properties(src/backend/sha2_avx2.cpp PROPERTIES
            COMPILE_FLAGS "-mavx2 -mbmi2")
        set_source_files_properties(src/backend/keccak_avx2.cpp PROPERTIES
            COMPILE_FLAGS "-mavx2")
        set_source_files_properties(src/backend/sha2_avx512.cpp PROPERTIES
            COMPILE_FLAGS "-mavx512f -mavx512ifma")
        set_source_files_properties(src/backend/keccak_avx512.cpp PROPERTIES
            COMPILE_FLAGS "-mavx512f -mavx512ifma")
        set_source_files_properties(src/backend/sha2_bmi2_adx.cpp PROPERTIES
            COMPILE_FLAGS "-mbmi2 -madx")
    elseif(MSVC)
        set_source_files_properties(src/backend/sha2_avx2.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX2")
        set_source_files_properties(src/backend/keccak_avx2.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX2")
        set_source_files_properties(src/backend/sha2_avx512.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX512")
        set_source_files_properties(src/backend/keccak_avx512.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX512")
        # BMI2/ADX implied by /arch:AVX2 on MSVC
        set_source_files_properties(src/backend/sha2_bmi2_adx.cpp PROPERTIES
            COMPILE_FLAGS "/arch:AVX2")
    endif()
endif()

# --- Per-backend ARM64 crypto extension compile flags ---
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64" AND NOT FORCE_PORTABLE)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        set_source_files_properties(src/backend/sha2_arm_ce.cpp PROPERTIES
            COMPILE_FLAGS "-march=armv8.2-a+crypto+sha3")
        set_source_files_properties(src/backend/keccak_arm_ce.cpp PROPERTIES
            COMPILE_FLAGS "-march=armv8.2-a+sha3")
    endif()
    # MSVC on ARM64: crypto extensions are enabled by default, no extra flags needed
endif()

# --- Tests ---
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# --- Benchmarks ---
if(BUILD_BENCHMARKS)
    add_subdirectory(bench)
endif()

# --- Fuzzing (Clang only) ---
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_subdirectory(fuzz)
endif()
