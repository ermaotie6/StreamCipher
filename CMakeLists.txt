cmake_minimum_required(VERSION 3.20)
project(streamcipher VERSION 0.1.0 LANGUAGES CXX)

# Library-only defaults when embedded. Do not change the parent C++ standard.
set(STREAMCIPHER_TOP_LEVEL OFF)
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    set(STREAMCIPHER_TOP_LEVEL ON)
endif()
option(STREAMCIPHER_BUILD_TESTS "Build unit tests" ${STREAMCIPHER_TOP_LEVEL})
option(STREAMCIPHER_BUILD_BENCHMARKS "Build benchmarks" OFF)
option(STREAMCIPHER_BUILD_EXAMPLES "Build examples" ${STREAMCIPHER_TOP_LEVEL})
option(STREAMCIPHER_BUILD_APPS "Build CLI application" ${STREAMCIPHER_TOP_LEVEL})
option(STREAMCIPHER_FETCH_DEPENDENCIES "Allow downloading missing test/benchmark dependencies" ${STREAMCIPHER_TOP_LEVEL})
option(STREAMCIPHER_USE_SIMD "Enable SIMD acceleration" ON)
option(STREAMCIPHER_USE_AESNI "Enable AES-NI intrinsics" ON)
option(STREAMCIPHER_ENABLE_ASAN "Enable AddressSanitizer for this project's targets" OFF)
include(GNUInstallDirs)

# ── Architecture Detection ──────────────────────────────────
include(cmake/DetectArch.cmake)

# ── Library Target ──────────────────────────────────────────
add_library(streamcipher)

add_library(streamcipher::streamcipher ALIAS streamcipher)
set_target_properties(streamcipher PROPERTIES
    WINDOWS_EXPORT_ALL_SYMBOLS ON CXX_EXTENSIONS OFF
    VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})

target_sources(streamcipher PRIVATE
    # Core
    src/core/gf.cpp
    src/core/bitslice.cpp
    src/core/aes.cpp
    src/core/aes_dispatch.cpp
    src/core/parameters.cpp
    src/core/ghash.cpp
    src/core/cipher.cpp
    # Stream
    src/stream/stream.cpp
    src/stream/pipeline.cpp
    # SIMD
    src/simd/simd.cpp
    src/simd/aesni.cpp
    # Memory
    src/memory/secure.cpp
)

target_include_directories(streamcipher
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_compile_features(streamcipher PUBLIC cxx_std_20)
target_compile_options(streamcipher PUBLIC $<$<CXX_COMPILER_ID:MSVC>:/utf-8>)

# ── SIMD Compile Definitions ────────────────────────────────
if(STREAMCIPHER_USE_SIMD)
    target_compile_definitions(streamcipher PRIVATE STREAMCIPHER_SIMD)
endif()
if(STREAMCIPHER_USE_AESNI)
    target_compile_definitions(streamcipher PRIVATE STREAMCIPHER_AESNI)
endif()

# ── Compiler Flags ──────────────────────────────────────────
target_compile_options(streamcipher PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall -Wextra -Wpedantic>
    $<$<CXX_COMPILER_ID:MSVC>:/W4>
)
# AES instructions are isolated in runtime-dispatched functions. Do not enable
# AVX2/AES globally: doing so makes even the software fallback require that CPU.

# ── Install ─────────────────────────────────────────────────
install(TARGETS streamcipher
    EXPORT  streamcipherTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(EXPORT streamcipherTargets NAMESPACE streamcipher::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/streamcipher)
install(DIRECTORY include/streamcipher DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
include(CMakePackageConfigHelpers)
configure_package_config_file(cmake/streamcipherConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/streamcipherConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/streamcipher)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/streamcipherConfigVersion.cmake
    VERSION ${PROJECT_VERSION} COMPATIBILITY SameMinorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/streamcipherConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/streamcipherConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/streamcipher)

# Scoped development options. Source-built tooling must use the same MSVC annotations.
function(streamcipher_instrument target visibility)
    if(NOT STREAMCIPHER_ENABLE_ASAN)
        return()
    endif()
    if(MSVC)
        target_compile_options(${target} ${visibility} /fsanitize=address /Zi)
        target_link_options(${target} ${visibility} /INCREMENTAL:NO /DEBUG)
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
        target_compile_options(${target} ${visibility} -fsanitize=address -fno-omit-frame-pointer)
        target_link_options(${target} ${visibility} -fsanitize=address)
    else()
        message(FATAL_ERROR "AddressSanitizer is unsupported by this compiler configuration")
    endif()
endfunction()
streamcipher_instrument(streamcipher PUBLIC)

install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/streamcipher)

# ── Subdirectories ──────────────────────────────────────────
function(streamcipher_copy_runtime target)
    if(WIN32 AND BUILD_SHARED_LIBS)
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:streamcipher> $<TARGET_FILE_DIR:${target}>
            VERBATIM)
    endif()
endfunction()

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

# A self-contained CLI/SDK archive. Development dependencies are never installed.
if(STREAMCIPHER_TOP_LEVEL)
    install(FILES README.md AGENTS.md LICENSE
        DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/streamcipher)
    install(DIRECTORY docs/ DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/streamcipher/docs)
    install(FILES docs/delivery.zh-CN.md DESTINATION . RENAME DELIVERY.md)
    if(MSVC AND STREAMCIPHER_BUILD_APPS)
        set(CMAKE_INSTALL_SYSTEM_RUNTIME_DESTINATION ${CMAKE_INSTALL_BINDIR})
        include(InstallRequiredSystemLibraries)
    endif()
    set(CPACK_GENERATOR ZIP)
    set(CPACK_PACKAGE_NAME streamcipher)
    set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
    set(CPACK_PACKAGE_FILE_NAME "streamcipher-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}-${STREAMCIPHER_ARCH}")
    include(CPack)
endif()
