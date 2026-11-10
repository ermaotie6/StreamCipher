# Apps — command-line tool

add_executable(scipher main.cpp options.cpp commands.cpp)
target_link_libraries(scipher PRIVATE streamcipher)
streamcipher_copy_runtime(scipher)
install(TARGETS scipher RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
if(MINGW)
    target_link_options(scipher PRIVATE -municode)
endif()
