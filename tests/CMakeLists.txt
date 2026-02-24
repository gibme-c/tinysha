add_executable(tinysha_tests
    test_main.cpp
    test_sha256.cpp
    test_sha384.cpp
    test_sha512.cpp
    test_sha3_256.cpp
    test_sha3_384.cpp
    test_sha3_512.cpp
    test_hmac.cpp
    test_pbkdf2.cpp
    test_truncation.cpp
    test_cpuid.cpp
)

target_link_libraries(tinysha_tests PRIVATE tinysha)
target_include_directories(tinysha_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
set_target_properties(tinysha_tests PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

# Warning flags for tests
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(tinysha_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set_property(TARGET tinysha_tests APPEND_STRING PROPERTY LINK_FLAGS
            " -Wl,-z,relro,-z,now -Wl,-z,noexecstack")
    endif()
    # macOS: -bind_at_load is deprecated on modern macOS (eager binding is the default)
    if(MINGW)
        set_property(TARGET tinysha_tests APPEND_STRING PROPERTY LINK_FLAGS
            " -Wl,--nxcompat -Wl,--dynamicbase -Wl,--high-entropy-va")
    endif()
elseif(MSVC)
    target_compile_options(tinysha_tests PRIVATE /W4 /WX)
    set_property(TARGET tinysha_tests APPEND_STRING PROPERTY LINK_FLAGS
        " /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA")
endif()

add_test(NAME tinysha_tests COMMAND tinysha_tests)
