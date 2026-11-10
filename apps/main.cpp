#include "options.hpp"
#include <exception>
#include <iostream>
#include <vector>
#include <string>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace {
int run(const std::vector<std::string>& owned) {
    std::vector<std::string_view> args;
    for (const auto& arg : owned) args.emplace_back(arg);
    const auto options = streamcipher::cli::parse(args);
    return streamcipher::cli::execute(options);
}
}

#ifdef _WIN32
// Convert native Windows arguments once at the app boundary. The parser uses UTF-8.
int wmain(int argc, wchar_t* argv[]) try {
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[i], -1, nullptr, 0, nullptr, nullptr);
        if (size == 0) throw std::invalid_argument("Invalid Unicode argument");
        std::string value(static_cast<size_t>(size), '\0');
        if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[i], -1, value.data(), size, nullptr, nullptr))
            throw std::invalid_argument("Cannot convert Unicode argument");
        value.pop_back();
        args.push_back(std::move(value));
    }
    return run(args);
#else
int main(int argc, char* argv[]) try {
    return run(std::vector<std::string>(argv + 1, argv + argc));
#endif
} catch (const std::exception& error) {
    std::cerr << "Error: " << error.what() << '\n';
    return 1;
}
