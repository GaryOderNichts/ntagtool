#pragma once

#include <cstddef>
#include <span>

namespace crypto {

bool CryptAesCTR(const std::span<const std::byte>& key, const std::span<const std::byte, 0x10>& nonce, const std::span<const std::byte>& inData, const std::span<std::byte>& outData);

bool EncryptAesCBC(const std::span<const std::byte>& key, const std::span<const std::byte, 0x10>& iv, const std::span<const std::byte>& inData, const std::span<std::byte>& outData);

bool DecryptAesCBC(const std::span<const std::byte>& key, const std::span<const std::byte, 0x10>& iv, const std::span<const std::byte>& inData, const std::span<std::byte>& outData);

bool GenerateHMAC(const std::span<const std::byte>& key, const std::span<const std::byte>& inData, const std::span<std::byte, 0x20>& outData);

} // namespace crypto
