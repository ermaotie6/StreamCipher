#include "options.hpp"
#include <charconv>
#include <limits>
#include <string>
#include <unordered_set>

namespace streamcipher::cli {
namespace {
uint64_t positive(std::string_view value, bool suffix) {
    uint64_t factor = 1;
    if (suffix && !value.empty()) {
        switch (value.back()) {
        case 'k': case 'K': factor = 1ull << 10; value.remove_suffix(1); break;
        case 'm': case 'M': factor = 1ull << 20; value.remove_suffix(1); break;
        case 'g': case 'G': factor = 1ull << 30; value.remove_suffix(1); break;
        }
    }
    uint64_t number = 0;
    if (value.empty()) throw std::invalid_argument("Empty numeric option");
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), number);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || number == 0 ||
        number > (std::numeric_limits<uint64_t>::max)() / factor)
        throw std::invalid_argument("Invalid positive numeric option");
    return number * factor;
}
void hex(std::string_view value, std::span<uint8_t> bytes) {
    if (value.size() != bytes.size() * 2) throw std::invalid_argument("Invalid key/nonce hex length");
    const auto digit = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < bytes.size(); ++i) {
        const auto hi = digit(value[2*i]), lo = digit(value[2*i+1]);
        if (hi < 0 || lo < 0) throw std::invalid_argument("Invalid key/nonce hex digit");
        bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
}
}
Options parse(std::span<const std::string_view> args) {
    if (args.empty()) throw std::invalid_argument("A command is required; use --help");
    Options result;
    if (args[0] == "--help" || args[0] == "-h") {
        if (args.size() != 1) throw std::invalid_argument("Help accepts no options");
        return result;
    }
    if (args[0] == "encrypt") result.command = Command::Encrypt;
    else if (args[0] == "decrypt") result.command = Command::Decrypt;
    else if (args[0] == "benchmark") result.command = Command::Benchmark;
    else throw std::invalid_argument("Unknown command; use --help");
    const bool file = result.command != Command::Benchmark;
    size_t i = 1;
    if (file) {
        if (args.size() < 3) throw std::invalid_argument("Input and output files required");
        result.input = std::filesystem::u8path(args[i++]);
        result.output = std::filesystem::u8path(args[i++]);
    }
    std::unordered_set<std::string_view> seen;
    for (; i < args.size(); ++i) {
        const auto option = args[i];
        if (!seen.insert(option).second) throw std::invalid_argument("Duplicate option");
        if (file && option == "--no-progress") { result.progress = false; continue; }
        if (++i == args.size()) throw std::invalid_argument("Missing option value");
        const auto value = args[i];
        if (file && option == "--mode") {
            if (value == "ctr") result.mode = cipher::Mode::CTR;
            else if (value == "gcm") result.mode = cipher::Mode::GCM;
            else throw std::invalid_argument("Mode must be ctr or gcm");
        } else if (file && option == "--key") hex(value, result.key);
        else if (file && option == "--nonce") hex(value, result.nonce);
        else if (file && option == "--chunk-size") {
            const auto count = positive(value, true);
            if (count > (std::numeric_limits<size_t>::max)()) throw std::length_error("Chunk size too large");
            result.chunk_size = static_cast<size_t>(count);
        } else if (!file && option == "--size") result.size = positive(value, true);
        else if (!file && option == "--iterations") result.iterations = positive(value, false);
        else throw std::invalid_argument("Unknown option for this command");
    }
    if (file && (!seen.contains("--key") || !seen.contains("--nonce")))
        throw std::invalid_argument("Both --key and --nonce are required");
    if (!file) {
        cipher::validate_length(cipher::Mode::CTR, 0, result.size);
        if (result.size > (std::numeric_limits<size_t>::max)()) throw std::length_error("Benchmark buffer too large");
    }
    return result;
}
}
