# Detect CPU architecture and set SIMD compile flags

if(NOT DEFINED STREAMCIPHER_ARCH)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64)|(AMD64|amd64)")
        set(STREAMCIPHER_ARCH "x86_64")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64|arm64")
        set(STREAMCIPHER_ARCH "aarch64")
    else()
        set(STREAMCIPHER_ARCH "generic")
    endif()
endif()

message(STATUS "Detected target architecture: ${STREAMCIPHER_ARCH}")

# Disable AES-NI on non-x86
if(NOT STREAMCIPHER_ARCH STREQUAL "x86_64")
    set(STREAMCIPHER_USE_AESNI OFF)
    message(STATUS "AES-NI disabled (requires x86_64)")
endif()
