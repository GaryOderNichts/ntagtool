#pragma once

#include <array>
#include <memory>
#include <span>

class Keys {
public:
    Keys();
    virtual ~Keys();

    // ntagtool.conf
    static std::shared_ptr<Keys> FromConfiguration();
    // key-retail.bin
    static std::shared_ptr<Keys> FromKeyset(const std::span<const std::byte, 160>& keyset);
    // locked-secret.bin, unfixed-info.bin
    static std::shared_ptr<Keys> FromBins(const std::span<const std::byte, 80>& unfixedInfo, const std::span<const std::byte, 80>& lockedSecret);

    bool HasNfcKey() const;
    const std::array<std::byte, 0x10>& GetNfcKey() const;
    const std::array<std::byte, 0x10>& GetNfcNonce() const;
    const std::array<std::byte, 0x20>& GetNfcXorPad() const;

    const std::array<std::byte, 0xe>& GetUnfixedInfosString() const;
    const std::array<std::byte, 0xe>& GetUnfixedInfosMagicBytes() const;
    const std::array<std::byte, 0x40>& GetUnfixedInfosHmacKey() const; 

    const std::array<std::byte, 0xe>& GetLockedSecretString() const;
    const std::array<std::byte, 0x10>& GetLockedSecretMagicBytes() const;
    const std::array<std::byte, 0x40>& GetLockedSecretHmacKey() const; 

private:
    std::array<std::byte, 0x10> mNfcKey;
    std::array<std::byte, 0x10> mNfcNonce;
    std::array<std::byte, 0x20> mNfcXorPad;

    std::array<std::byte, 0xe> mUnfixedInfosString;
    std::array<std::byte, 0xe> mUnfixedInfosMagicBytes;
    std::array<std::byte, 0x40> mUnfixedInfosHmacKey;

    std::array<std::byte, 0xe> mLockedSecretString;
    std::array<std::byte, 0x10> mLockedSecretMagicBytes;
    std::array<std::byte, 0x40> mLockedSecretHmacKey;
};
