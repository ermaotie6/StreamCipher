# Benchmarks — Google Benchmark

include(FetchContent)

FetchContent_Declare(
    google_benchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG        v1.9.1
)
FetchContent_MakeAvailable(google_benchmark)

add_executable(bench_gf      bench_gf.cpp)
add_executable(bench_aes     bench_aes.cpp)
add_executable(bench_stream  bench_stream.cpp)

foreach(target bench_gf bench_aes bench_stream)
    target_link_libraries(${target} PRIVATE streamcipher benchmark::benchmark)
endforeach()
