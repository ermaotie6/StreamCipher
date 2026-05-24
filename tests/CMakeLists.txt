# Tests — Catch2 unit tests

include(FetchContent)

FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v3.7.1
)
FetchContent_MakeAvailable(Catch2)

add_executable(test_gf        test_gf.cpp)
add_executable(test_aes       test_aes.cpp)
add_executable(test_stream    test_stream.cpp)
add_executable(test_simd      test_simd.cpp)

foreach(target test_gf test_aes test_stream test_simd)
    target_link_libraries(${target} PRIVATE streamcipher Catch2::Catch2WithMain)
endforeach()

add_test(NAME gf       COMMAND test_gf)
add_test(NAME aes      COMMAND test_aes)
add_test(NAME stream   COMMAND test_stream)
add_test(NAME simd     COMMAND test_simd)
