if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    return()
endif()

# libFuzzer runtime on Windows has CRT mismatches (iterator debug level
# in Debug, static vs dynamic CRT in Release). Skip fuzz on Windows.
if(WIN32)
    return()
endif()

set(FUZZ_TARGETS
    fuzz_sha256
    fuzz_sha384
    fuzz_sha512
    fuzz_sha3_256
    fuzz_sha3_384
    fuzz_sha3_512
    fuzz_hmac
    fuzz_pbkdf2
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
    target_compile_options(${target} PRIVATE
        -Wall -Wextra -Wpedantic -Werror
        -fsanitize=fuzzer,address
    )
    set_property(TARGET ${target} APPEND_STRING PROPERTY LINK_FLAGS " -fsanitize=fuzzer,address")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set_property(TARGET ${target} APPEND_STRING PROPERTY LINK_FLAGS
            " -Wl,-z,relro,-z,now -Wl,-z,noexecstack")
    endif()
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        set_property(TARGET ${target} APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-bind_at_load")
    endif()
endforeach()
