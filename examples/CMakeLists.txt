# Examples — minimal usage demonstrations

add_executable(encrypt_file encrypt_file.cpp)
add_executable(decrypt_file decrypt_file.cpp)

foreach(target encrypt_file decrypt_file)
    target_link_libraries(${target} PRIVATE streamcipher)
endforeach()
