#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace streamcipher::cipher {
enum class Algorithm : uint8_t { AES_128 = 0 };
// ECB is retained as an enum value for source compatibility; factories reject it.
enum class Mode : uint8_t { ECB = 0, CTR = 1, GCM = 2 };
enum class Direction : uint8_t { Encrypt, Decrypt };

inline constexpr size_t KEY_SIZE = 16;
inline constexpr size_t NONCE_SIZE = 12;
inline constexpr size_t BLOCK_SIZE = 16;
inline constexpr size_t TAG_SIZE = 16;
inline constexpr uint64_t CTR_MAX_BYTES = (uint64_t{1} << 32) * BLOCK_SIZE;
inline constexpr uint64_t GCM_MAX_BYTES = ((uint64_t{1} << 32) - 2) * BLOCK_SIZE;

struct ModeSpec {
    size_t tag_size;
    uint32_t initial_counter;
    uint64_t max_payload;
};
[[nodiscard]] ModeSpec mode_spec(Mode mode);
void validate_parameters(Algorithm algo, Mode mode);
void validate_length(Mode mode, uint64_t processed, uint64_t additional);
// Checked wire-size helpers; reject unsupported modes, truncation and counter exhaustion.
[[nodiscard]] uint64_t encrypted_size(Mode mode, uint64_t payload);
[[nodiscard]] uint64_t decrypted_size(Mode mode, uint64_t encoded);

class AuthenticationError : public std::runtime_error {
public:
    AuthenticationError() : std::runtime_error("GCM authentication failed") {}
};
} // namespace streamcipher::cipher
