cmake_minimum_required(VERSION 3.20)
project(streamcipher_manual_examples LANGUAGES CXX)

find_package(streamcipher 0.1 CONFIG REQUIRED)
foreach(example memory_gcm stream_modes file_gcm core_and_memory)
    add_executable(${example} ${example}.cpp)
    target_link_libraries(${example} PRIVATE streamcipher::streamcipher)
endforeach()
