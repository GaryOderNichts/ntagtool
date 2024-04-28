#pragma once

#include <array>
#include <memory>
#include <span>


class Tag;
class Keys;

class TagEncryption {
public:
    TagEncryption(std::shared_ptr<Tag> tag, std::shared_ptr<Keys> keys);
    ~TagEncryption();

    bool InitializeInternalKeys();

    bool ValidateLockedSecretHMAC();
    bool ValidateUnfixedInfosHMAC();

    bool UpdateLockedSecretHMAC();
    bool UpdateUnfixedInfosHMAC();

    bool EncryptTag();
    bool DecryptTag();

private:
    bool GenerateKeyGenSalt();
    bool GenerateInternalKeys();

    bool CryptTag();
    bool GenerateLockedSecretHMAC(const std::span<std::byte, 0x20>& hmac);
    bool GenerateUnfixedInfosHMAC(const std::span<std::byte, 0x20>& hmac);

    std::shared_ptr<Tag> mTag;
    std::shared_ptr<Keys> mKeys;

    std::array<std::byte, 0x20> mKeyGenSalt;

    std::array<std::byte, 0x10> mLockedSecretKey;
    std::array<std::byte, 0x10> mLockedSecretNonce;
    std::array<std::byte, 0x40> mLockedSecretDerivedHmacKey;

    std::array<std::byte, 0x10> mUnfixedInfosKey;
    std::array<std::byte, 0x10> mUnfixedInfosNonce;
    std::array<std::byte, 0x40> mUnfixedInfosDerivedHmacKey;
};
