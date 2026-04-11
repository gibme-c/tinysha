if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    return()
endif()

# libFuzzer is only reliably available on Linux Clang.
# macOS: Apple Clang lacks the runtime; Homebrew LLVM has ABI mismatches
# with macOS system libc++. Windows: CRT mismatches in Debug/Release.
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    return()
endif()

set(FUZZ_TARGETS
    fuzz_sha256
    fuzz_sha384
    fuzz_sha512
    fuzz_sha3_256
    fuzz_sha3_384
    fuzz_sha3_512
    fuzz_hmac_sha256
    fuzz_hmac_sha384
    fuzz_hmac_sha512
    fuzz_hmac_sha3_256
    fuzz_hmac_sha3_384
    fuzz_hmac_sha3_512
    fuzz_pbkdf2_sha256
    fuzz_pbkdf2_sha384
    fuzz_pbkdf2_sha512
    fuzz_pbkdf2_sha3_256
    fuzz_pbkdf2_sha3_384
    fuzz_pbkdf2_sha3_512
    fuzz_truncation
)

foreach(target ${FUZZ_TARGETS})
    add_executable(${target} ${target}.cpp)
    target_link_libraries(${target} PRIVATE tinysha)
    set_target_properties(${target} PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
    )
    target_include_directories(${target} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    # Sanitizer stack: libFuzzer (coverage-guided driver) + ASan (memory safety)
    # + UBSan (undefined behavior). -fno-sanitize-recover=all turns every UBSan
    # finding into an immediate abort, which is what libFuzzer treats as a bug.
    target_compile_options(${target} PRIVATE
        -Wall -Wextra -Wpedantic -Werror
        -fsanitize=fuzzer,address,undefined
        -fno-sanitize-recover=all
        -fno-omit-frame-pointer
        -g
    )
    set_property(TARGET ${target} APPEND_STRING PROPERTY LINK_FLAGS
        " -fsanitize=fuzzer,address,undefined")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set_property(TARGET ${target} APPEND_STRING PROPERTY LINK_FLAGS
            " -Wl,-z,relro,-z,now -Wl,-z,noexecstack")
    endif()
    # macOS: -bind_at_load is deprecated on modern macOS (eager binding is the default)
endforeach()
