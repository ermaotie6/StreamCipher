#pragma once
#include <filesystem>
#include <fstream>
#include <random>
#include <span>
#include <cstdint>
#include <stdexcept>
#include <system_error>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <sys/stat.h>
#endif

namespace streamcipher::detail {
// Directory creation must be exclusive; POSIX permissions apply at creation.
// Windows inherits the destination directory ACL. Use a private destination directory.
inline bool create_private_directory(const std::filesystem::path& path) {
#ifdef _WIN32
    return std::filesystem::create_directory(path);
#else
    if (::mkdir(path.c_str(), 0700) == 0) return true;
    if (errno == EEXIST) return false;
    throw std::system_error(errno, std::generic_category(), "Cannot create staging directory");
#endif
}
// Same-filesystem publication; exception cleanup is best effort, not crash recovery.
class OutputTransaction {
public:
    explicit OutputTransaction(const std::filesystem::path& output) : output_(output) {
        std::random_device rng;
        for (int attempt = 0; attempt < 128; ++attempt) {
            auto candidate = output.parent_path() / (".scipher-" + std::to_string(rng()) + "-" + std::to_string(rng()));
            if (create_private_directory(candidate)) { directory_ = candidate; break; }
        }
        if (directory_.empty()) throw std::runtime_error("Cannot create staging directory");
        try {
            std::filesystem::permissions(directory_, std::filesystem::perms::owner_all);
            file_ = directory_ / "output";
            stream.exceptions(std::ios::failbit | std::ios::badbit);
            stream.open(file_, std::ios::binary);
            std::filesystem::permissions(file_, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
        } catch (...) { cleanup(); throw; }
    }
    ~OutputTransaction() { cleanup(); }
    OutputTransaction(const OutputTransaction&) = delete;
    OutputTransaction& operator=(const OutputTransaction&) = delete;
    void write(std::span<const uint8_t> bytes) {
        if (!bytes.empty())
            stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    void publish() {
        stream.close(); // Includes checking the final flush.
#ifdef _WIN32
        if (!MoveFileExW(file_.c_str(), output_.c_str(), MOVEFILE_REPLACE_EXISTING))
            throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "Cannot publish output");
#else
        std::filesystem::rename(file_, output_);
#endif
    }
private:
    std::ofstream stream;
    void cleanup() noexcept {
        stream.exceptions(std::ios::goodbit);
        if (stream.is_open()) stream.close();
        std::error_code ignored;
        if (!file_.empty()) std::filesystem::remove(file_, ignored);
        if (!directory_.empty()) std::filesystem::remove(directory_, ignored);
    }
    std::filesystem::path output_, directory_, file_;
};
} // namespace streamcipher::detail
