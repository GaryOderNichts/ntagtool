#include "crypto.hpp"

#include <cstdint>
#include <array>

#include <mbedtls/aes.h>
#include <mbedtls/md.h>

bool crypto::CryptAesCTR(const std::span<const std::byte>& key, const std::span<const std::byte, 0x10>& nonce, const std::span<const std::byte>& inData, const std::span<std::byte>& outData)
{
    if (inData.size() != outData.size()) {
        return false;
    }

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    // For AES-CTR mbedtls_aes_setkey_enc is used for both decrypt and encrypt
    if (mbedtls_aes_setkey_enc(&ctx, reinterpret_cast<const uint8_t*>(key.data()), key.size() * 8) != 0) {
        mbedtls_aes_free(&ctx);
        return false;
    }

    // Create a copy of the nonce since mbedtls will modify it
    std::array<std::byte, 0x10> _nonce;
    std::copy(nonce.begin(), nonce.end(), _nonce.begin());

    size_t ncOff = 0;
    std::array<uint8_t, 0x10> streamBlock{};
    if (mbedtls_aes_crypt_ctr(&ctx, inData.size(), &ncOff, reinterpret_cast<uint8_t*>(_nonce.data()), streamBlock.data(), reinterpret_cast<const uint8_t*>(inData.data()), reinterpret_cast<uint8_t*>(outData.data())) != 0) {
        mbedtls_aes_free(&ctx);
        return false;
    }

    mbedtls_aes_free(&ctx);
    return true;
}

bool crypto::EncryptAesCBC(const std::span<const std::byte>& key, const std::span<const std::byte, 0x10>& iv, const std::span<const std::byte>& inData, const std::span<std::byte>& outData)
{
    if (inData.size() != outData.size()) {
        return false;
    }

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    if (mbedtls_aes_setkey_enc(&ctx, reinterpret_cast<const uint8_t*>(key.data()), key.size() * 8) != 0) {
        mbedtls_aes_free(&ctx);
        return false;
    }

    // Create a copy of the iv since mbedtls will modify it
    std::array<std::byte, 0x10> _iv;
    std::copy(iv.begin(), iv.end(), _iv.begin());

    if (mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, inData.size(), reinterpret_cast<uint8_t*>(_iv.data()), reinterpret_cast<const uint8_t*>(inData.data()), reinterpret_cast<uint8_t*>(outData.data())) != 0) {
        mbedtls_aes_free(&ctx);
        return false;
    }

    mbedtls_aes_free(&ctx);
    return true;
}

bool crypto::DecryptAesCBC(const std::span<const std::byte>& key, const std::span<const std::byte, 0x10>& iv, const std::span<const std::byte>& inData, const std::span<std::byte>& outData)
{
    if (inData.size() != outData.size()) {
        return false;
    }

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    if (mbedtls_aes_setkey_dec(&ctx, reinterpret_cast<const uint8_t*>(key.data()), key.size() * 8) != 0) {
        mbedtls_aes_free(&ctx);
        return false;
    }

    // Create a copy of the iv since mbedtls will modify it
    std::array<std::byte, 0x10> _iv;
    std::copy(iv.begin(), iv.end(), _iv.begin());

    if (mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, inData.size(), reinterpret_cast<uint8_t*>(_iv.data()), reinterpret_cast<const uint8_t*>(inData.data()), reinterpret_cast<uint8_t*>(outData.data())) != 0) {
        mbedtls_aes_free(&ctx);
        return false;
    }

    mbedtls_aes_free(&ctx);
    return true;
}

bool crypto::GenerateHMAC(const std::span<const std::byte>& key, const std::span<const std::byte>& inData, const std::span<std::byte, 0x20>& outData)
{
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return mbedtls_md_hmac(info, reinterpret_cast<const uint8_t*>(key.data()), key.size(), reinterpret_cast<const uint8_t*>(inData.data()), inData.size(), reinterpret_cast<uint8_t*>(outData.data())) == 0;
}
