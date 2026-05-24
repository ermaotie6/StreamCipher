cmake_minimum_required(VERSION 3.20)
project(streamcipher VERSION 0.1.0 LANGUAGES CXX)

# ── C++ Standard ────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Compiler Options ────────────────────────────────────────
option(STREAMCIPHER_BUILD_TESTS      "Build unit tests"        ON)
option(STREAMCIPHER_BUILD_BENCHMARKS "Build benchmarks"        ON)
option(STREAMCIPHER_BUILD_EXAMPLES   "Build examples"          ON)
option(STREAMCIPHER_BUILD_APPS       "Build CLI application"   ON)
option(STREAMCIPHER_USE_SIMD         "Enable SIMD acceleration" ON)
option(STREAMCIPHER_USE_AESNI        "Enable AES-NI intrinsics" ON)

# ── Architecture Detection ──────────────────────────────────
include(cmake/DetectArch.cmake)

# ── Library Target ──────────────────────────────────────────
add_library(streamcipher)

add_library(streamcipher::streamcipher ALIAS streamcipher)

target_sources(streamcipher PRIVATE
    # Core
    src/core/gf.cpp
    src/core/bitslice.cpp
    src/core/aes.cpp
    src/core/cipher.cpp
    # Stream
    src/stream/stream.cpp
    src/stream/pipeline.cpp
    # SIMD
    src/simd/simd.cpp
    src/simd/aesni.cpp
    # Memory
    src/memory/pool.cpp
    src/memory/span_utils.cpp
)

target_include_directories(streamcipher
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# ── SIMD Compile Definitions ────────────────────────────────
if(STREAMCIPHER_USE_SIMD)
    target_compile_definitions(streamcipher PUBLIC STREAMCIPHER_SIMD)
endif()
if(STREAMCIPHER_USE_AESNI)
    target_compile_definitions(streamcipher PUBLIC STREAMCIPHER_AESNI)
endif()

# ── Compiler Flags ──────────────────────────────────────────
target_compile_options(streamcipher PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall -Wextra -Wpedantic>
    $<$<CXX_COMPILER_ID:MSVC>:/W4>
)
if(STREAMCIPHER_USE_SIMD AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    target_compile_options(streamcipher PRIVATE -maes -msse4.1 -mavx2)
endif()

# ── Install ─────────────────────────────────────────────────
include(GNUInstallDirs)
install(TARGETS streamcipher
    EXPORT  streamcipherTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/streamcipher DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# ── Subdirectories ──────────────────────────────────────────
if(STREAMCIPHER_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(STREAMCIPHER_BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()

if(STREAMCIPHER_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(STREAMCIPHER_BUILD_APPS)
    add_subdirectory(apps)
endif()
