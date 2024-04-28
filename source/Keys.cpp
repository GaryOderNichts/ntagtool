#include "Keys.hpp"

#include <algorithm>
#include <iostream>

Keys::Keys()
 : mNfcKey()
{
}

Keys::~Keys()
{
}

std::shared_ptr<Keys> Keys::FromConfiguration()
{
    // TODO
    return {};
}

std::shared_ptr<Keys> Keys::FromKeyset(const std::span<const std::byte, 160>& keyset)
{
    return FromBins(keyset.subspan<0, 80>(), keyset.subspan<80, 80>());
}

std::shared_ptr<Keys> Keys::FromBins(const std::span<const std::byte, 80>& unfixedInfo, const std::span<const std::byte, 80>& lockedSecret)
{
    std::shared_ptr<Keys> keys = std::make_shared<Keys>();

    // HMAC key (only the first 0x10 bytes are used, the rest is zero padded)
    std::copy_n(unfixedInfo.begin(), 0x10, keys->mUnfixedInfosHmacKey.begin());
    std::fill_n(keys->mUnfixedInfosHmacKey.begin() + 0x10, 0x30, std::byte(0));
    // String
    std::copy_n(unfixedInfo.begin() + 0x10, 0xe, keys->mUnfixedInfosString.begin());
    // Magic bytes
    std::copy_n(unfixedInfo.begin() + 0x20, 0xe, keys->mUnfixedInfosMagicBytes.begin());
    // XOR pad
    std::copy_n(unfixedInfo.begin() + 0x30, 0x20, keys->mNfcXorPad.begin());

    // HMAC key (only the first 0x10 bytes are used, the rest is zero padded)
    std::copy_n(lockedSecret.begin(), 0x10, keys->mLockedSecretHmacKey.begin());
    std::fill_n(keys->mLockedSecretHmacKey.begin() + 0x10, 0x30, std::byte(0));
    // String
    std::copy_n(lockedSecret.begin() + 0x10, 0xe, keys->mLockedSecretString.begin());
    // Magic bytes
    std::copy_n(lockedSecret.begin() + 0x20, 0x10, keys->mLockedSecretMagicBytes.begin());
    // XOR pad (this should be the same as the unfixedInfo one)
    if (!std::equal(keys->mNfcXorPad.begin(), keys->mNfcXorPad.end(), lockedSecret.begin() + 0x30)) {
        std::cerr << "Error: Locked Secret XOR padding does not match Unfixed Info XOR padding" << std::endl;
        return {};
    }

    return keys;
}

bool Keys::HasNfcKey() const
{
    return mNfcKey[0] != std::byte(0);
}

const std::array<std::byte, 0x10>& Keys::GetNfcKey() const
{
    return mNfcKey;
}

const std::array<std::byte, 0x10>& Keys::GetNfcNonce() const
{
    return mNfcNonce;
}

const std::array<std::byte, 0x20>& Keys::GetNfcXorPad() const
{
    return mNfcXorPad;
}

const std::array<std::byte, 0xe>& Keys::GetUnfixedInfosString() const
{
    return mUnfixedInfosString;
}

const std::array<std::byte, 0xe>& Keys::GetUnfixedInfosMagicBytes() const
{
    return mUnfixedInfosMagicBytes;
}

const std::array<std::byte, 0x40>& Keys::GetUnfixedInfosHmacKey() const
{
    return mUnfixedInfosHmacKey;
}

const std::array<std::byte, 0xe>& Keys::GetLockedSecretString() const
{
    return mLockedSecretString;
}

const std::array<std::byte, 0x10>& Keys::GetLockedSecretMagicBytes() const
{
    return mLockedSecretMagicBytes;
}

const std::array<std::byte, 0x40>& Keys::GetLockedSecretHmacKey() const
{
    return mLockedSecretHmacKey;
}
