#include "streamcipher/core/parameters.hpp"

namespace streamcipher::cipher {
ModeSpec mode_spec(Mode mode) {
    switch (mode) {
    case Mode::CTR: return {0, 0, CTR_MAX_BYTES};
    case Mode::GCM: return {TAG_SIZE, 2, GCM_MAX_BYTES};
    default: throw std::invalid_argument("Unsupported cipher mode");
    }
}
void validate_parameters(Algorithm algo, Mode mode) {
    if (algo != Algorithm::AES_128) throw std::invalid_argument("Unsupported cipher algorithm");
    (void)mode_spec(mode);
}
void validate_length(Mode mode, uint64_t processed, uint64_t additional) {
    const auto limit = mode_spec(mode).max_payload;
    if (processed > limit || additional > limit - processed)
        throw std::length_error("Cipher counter exhausted; use a new nonce");
}
uint64_t encrypted_size(Mode mode, uint64_t payload) {
    validate_length(mode, 0, payload);
    return payload + mode_spec(mode).tag_size; // Limits leave room for the tag.
}
uint64_t decrypted_size(Mode mode, uint64_t encoded) {
    const auto tag_size = mode_spec(mode).tag_size;
    if (encoded < tag_size) throw std::invalid_argument("Truncated GCM tag");
    const auto payload = encoded - tag_size;
    validate_length(mode, 0, payload);
    return payload;
}
} // namespace streamcipher::cipher
