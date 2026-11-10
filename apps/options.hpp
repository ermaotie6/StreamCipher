#pragma once
#include "streamcipher/core/parameters.hpp"
#include "streamcipher/memory/secure.hpp"
#include <array>
#include <filesystem>
#include <span>
#include <string_view>

namespace streamcipher::cli {
enum class Command { Help, Encrypt, Decrypt, Benchmark };
struct Options {
    Command command = Command::Help;
    cipher::Mode mode = cipher::Mode::CTR;
    std::filesystem::path input, output;
    std::array<uint8_t, cipher::KEY_SIZE> key{};
    std::array<uint8_t, cipher::NONCE_SIZE> nonce{};
    size_t chunk_size = 1 << 20;
    uint64_t size = 1 << 20, iterations = 10;
    bool progress = true;
    Options() = default;
    Options(const Options&) = delete;
    Options& operator=(const Options&) = delete;
    Options(Options&&) noexcept = default;
    Options& operator=(Options&&) = delete;
    ~Options() { memory::secure_zero(key); memory::secure_zero(nonce); }
};
// Parsing has no filesystem or encryption side effects.
[[nodiscard]] Options parse(std::span<const std::string_view> args);
void print_usage();
int execute(const Options& options);
}
