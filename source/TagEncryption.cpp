#include "TagEncryption.hpp"

#include "Tag.hpp"
#include "Keys.hpp"
#include "crypto.hpp"

#include <vector>
#include <algorithm>

namespace {

// ccr_nfc way of generating internal keys
bool GenerateKey(const std::span<const std::byte>& key, const std::span<const std::byte, 0xe>& name, const std::span<const std::byte, 0x40>& inData, const std::span<std::byte, 0x40>& outData)
{
    // Create a buffer containing 2 counter bytes, the key name, and the key data
    std::uint16_t counter = 0;
    std::array<std::byte, 0x50> buffer{};
    std::copy(name.begin(), name.end(), buffer.begin() + 2);
    std::copy(inData.begin(), inData.end(), buffer.begin() + name.size() + 2);

    std::size_t remaining = outData.size();
    std::size_t offset = 0;
    while (remaining > 0) {
        // Set counter bytes and increment counter
        buffer[0] = std::byte((counter >> 8) & 0xff);
        buffer[1] = std::byte(counter & 0xff);
        counter++;

        if (!crypto::GenerateHMAC(key, buffer, outData.subspan(offset).first<0x20>())) {
            return false;
        }

        offset += 0x20;
        remaining -= 0x20;
    }

    return true;
}

} // namespace

TagEncryption::TagEncryption(std::shared_ptr<Tag> tag, std::shared_ptr<Keys> keys)
 : mTag(std::move(tag)), mKeys(std::move(keys))
{
}

TagEncryption::~TagEncryption()
{
}

bool TagEncryption::InitializeInternalKeys()
{
    // Check for the supported tag versions
    if (mTag->GetVersion() != 0 && mTag->GetVersion() != 2) {
        return false;
    }

    if (!GenerateKeyGenSalt()) {
        return false;
    }

    if (!GenerateInternalKeys()) {
        return false;
    }

    return true;
}

bool TagEncryption::ValidateLockedSecretHMAC()
{
    if (mTag->IsEncrypted()) {
        return false;
    }

    // Generate HMAC
    std::array<std::byte, 0x20> hmac;
    if (!GenerateLockedSecretHMAC(hmac)) {
        return false;
    }

    // Validate
    return std::equal(hmac.begin(), hmac.end(), mTag->GetData().begin() + mTag->GetLockedSecretHmacOffset());
}

bool TagEncryption::ValidateUnfixedInfosHMAC()
{
    if (mTag->IsEncrypted()) {
        return false;
    }

    // Generate HMAC
    std::array<std::byte, 0x20> hmac;
    if (!GenerateUnfixedInfosHMAC(hmac)) {
        return false;
    }

    // Validate
    return std::equal(hmac.begin(), hmac.end(), mTag->GetData().begin() + mTag->GetUnfixedInfosHmacOffset());
}

bool TagEncryption::UpdateLockedSecretHMAC()
{
    if (mTag->IsEncrypted()) {
        return false;
    }

    // Generate HMAC
    std::array<std::byte, 0x20> hmac;
    if (!GenerateLockedSecretHMAC(hmac)) {
        return false;
    }

    // Update HMAC
    std::copy(hmac.begin(), hmac.end(), mTag->GetData().begin() + mTag->GetLockedSecretHmacOffset());
    return true;
}

bool TagEncryption::UpdateUnfixedInfosHMAC()
{
    if (mTag->IsEncrypted()) {
        return false;
    }

    // Generate HMAC
    std::array<std::byte, 0x20> hmac;
    if (!GenerateUnfixedInfosHMAC(hmac)) {
        return false;
    }

    // Update HMAC
    std::copy(hmac.begin(), hmac.end(), mTag->GetData().begin() + mTag->GetUnfixedInfosHmacOffset());
    return true;
}

bool TagEncryption::EncryptTag()
{
    if (mTag->IsEncrypted()) {
        return false;
    }

    if (!CryptTag()) {
        return false;
    }

    // Tag now contains encrypted data
    mTag->SetEncrypted(true);
    return true;
}

bool TagEncryption::DecryptTag()
{
    if (!mTag->IsEncrypted()) {
        return false;
    }

    if (!CryptTag()) {
        return false;
    }

    // Tag now contains decrypted data
    mTag->SetEncrypted(false);
    return true;
}

bool TagEncryption::GenerateKeyGenSalt()
{
    // If we have the Nfc Key we can just decrypt using AES-CTR
    if (mKeys->HasNfcKey()) {
        return crypto::CryptAesCTR(mKeys->GetNfcKey(), mKeys->GetNfcNonce(), mTag->GetData(mTag->GetKeyGenSaltOffset(), 0x20), mKeyGenSalt);
    }

    // Perform XOR with Xor pad
    std::transform(mKeys->GetNfcXorPad().begin(), mKeys->GetNfcXorPad().end(), mTag->GetData(mTag->GetKeyGenSaltOffset(), 0x20).begin(), mKeyGenSalt.begin(), std::bit_xor<std::byte>());
    return true;
}

bool TagEncryption::GenerateInternalKeys()
{
    std::array<std::byte, 0x40> lockedSecretBuffer{};
    std::array<std::byte, 0x40> unfixedInfosBuffer{};
    std::array<std::byte, 0x40> outBuffer{};

    // Fill the locked secret buffer
    std::copy(mKeys->GetLockedSecretMagicBytes().begin(), mKeys->GetLockedSecretMagicBytes().end(), lockedSecretBuffer.begin());
    if (mTag->GetVersion() == 0) {
        // For Version 0 this is the 16-byte Format Info: <https://wiiubrew.org/wiki/Rumble_U_NFC_Figures#Format_Info>
        std::copy_n(mTag->GetData().begin() + mTag->GetUidOffset(), 0x10, lockedSecretBuffer.begin() + 0x10);
    } else if (mTag->GetVersion() == 2) {
        // For Version 2 this is 2 times the 7-byte UID + 1 check byte
        std::copy_n(mTag->GetData().begin() + mTag->GetUidOffset(), 8, lockedSecretBuffer.begin() + 0x10);
        std::copy_n(mTag->GetData().begin() + mTag->GetUidOffset(), 8, lockedSecretBuffer.begin() + 0x18);
    } else {
        return false;
    }
    std::copy(mKeyGenSalt.begin(), mKeyGenSalt.end(), lockedSecretBuffer.begin() + 0x20);

    // Generate the key output
    if (!GenerateKey(mKeys->GetLockedSecretHmacKey(), mKeys->GetLockedSecretString(), lockedSecretBuffer, outBuffer)) {
        return false;
    }

    // First 0x10 bytes of the generated output is the locked secret key
    std::copy_n(outBuffer.begin(), 0x10, mLockedSecretKey.begin());
    // Nonce follows
    std::copy_n(outBuffer.begin() + 0x10, 0x10, mLockedSecretNonce.begin());
    // The first 0x10 bytes of the hmac key follows, the other 0x30 are zero padded
    std::copy_n(outBuffer.begin() + 0x20, 0x10, mLockedSecretDerivedHmacKey.begin());
    std::fill_n(mLockedSecretDerivedHmacKey.begin() + 0x10, 0x30, std::byte(0));
    // The last 0x10 bytes of the generated buffer are unused

    // Fill the unfixed infos buffer
    std::copy_n(mTag->GetData().begin() + mTag->GetSeedOffset(), 2, unfixedInfosBuffer.begin());
    std::copy_n(mKeys->GetUnfixedInfosMagicBytes().begin(), 0xe, unfixedInfosBuffer.begin() + 2);
    if (mTag->GetVersion() == 0) {
        // For Version 0 this is the 16-byte Format Info: <https://wiiubrew.org/wiki/Rumble_U_NFC_Figures#Format_Info>
        std::copy_n(mTag->GetData().begin() + mTag->GetUidOffset(), 0x10, unfixedInfosBuffer.begin() + 0x10);
    } else if (mTag->GetVersion() == 2) {
        // For Version 2 this is 2 times the 7-byte UID + 1 check byte
        std::copy_n(mTag->GetData().begin() + mTag->GetUidOffset(), 8, unfixedInfosBuffer.begin() + 0x10);
        std::copy_n(mTag->GetData().begin() + mTag->GetUidOffset(), 8, unfixedInfosBuffer.begin() + 0x18);
    } else {
        return false;
    }
    std::copy(mKeyGenSalt.begin(), mKeyGenSalt.end(), unfixedInfosBuffer.begin() + 0x20);

    // Generate the key output
    if (!GenerateKey(mKeys->GetUnfixedInfosHmacKey(), mKeys->GetUnfixedInfosString(), unfixedInfosBuffer, outBuffer)) {
        return false;
    }

    // First 0x10 bytes of the generated output is the unfixed infos key
    std::copy_n(outBuffer.begin(), 0x10, mUnfixedInfosKey.begin());
    // Nonce follows
    std::copy_n(outBuffer.begin() + 0x10, 0x10, mUnfixedInfosNonce.begin());
    // The first 0x10 bytes of the hmac key follows, the other 0x30 are zero padded
    std::copy_n(outBuffer.begin() + 0x20, 0x10, mUnfixedInfosDerivedHmacKey.begin());
    std::fill_n(mUnfixedInfosDerivedHmacKey.begin() + 0x10, 0x30, std::byte(0));
    // The last 0x10 bytes of the generated buffer are unused

    return true;
}

bool TagEncryption::CryptTag()
{
    std::vector<std::byte> cryptedLockedSecret;
    std::vector<std::byte> cryptedUnfixedInfos;

    // Version 0 tags have an encrypted locked secret area
    if (mTag->GetVersion() == 0) {
        cryptedLockedSecret.resize(mTag->GetLockedSecretSize());
        if (!crypto::CryptAesCTR(mLockedSecretKey, mLockedSecretNonce, mTag->GetData(mTag->GetLockedSecretOffset(), mTag->GetLockedSecretSize()), cryptedLockedSecret)) {
            return false;
        }
    }

    // Crypt unfixed infos
    cryptedUnfixedInfos.resize(mTag->GetUnfixedInfosSize());
    if (!crypto::CryptAesCTR(mUnfixedInfosKey, mUnfixedInfosNonce, mTag->GetData(mTag->GetUnfixedInfosOffset(), mTag->GetUnfixedInfosSize()), cryptedUnfixedInfos)) {
        return false;
    }

    // Update tag data
    if (mTag->GetVersion() == 0) {
        std::copy(cryptedLockedSecret.begin(), cryptedLockedSecret.end(), mTag->GetData().begin() + mTag->GetLockedSecretOffset());
    }
    std::copy(cryptedUnfixedInfos.begin(), cryptedUnfixedInfos.end(), mTag->GetData().begin() + mTag->GetUnfixedInfosOffset());

    return true;
}

bool TagEncryption::GenerateLockedSecretHMAC(const std::span<std::byte, 0x20>& hmac)
{
    if (mTag->IsEncrypted()) {
        return false;
    }

    return crypto::GenerateHMAC(mLockedSecretDerivedHmacKey, mTag->GetData(mTag->GetLockedSecretHmacOffset() + 0x20, (mTag->GetDataSize() - mTag->GetLockedSecretHmacOffset()) - 0x20), hmac);
}

bool TagEncryption::GenerateUnfixedInfosHMAC(const std::span<std::byte, 0x20>& hmac)
{
    if (mTag->IsEncrypted()) {
        return false;
    }

    size_t offset;
    size_t size;
    if (mTag->GetVersion() == 0) {
        offset = mTag->GetUnfixedInfosHmacOffset() + 0x20;
        size = (mTag->GetDataSize() - mTag->GetUnfixedInfosHmacOffset()) - 0x20;
    } else {
        offset = mTag->GetUnfixedInfosHmacOffset() + 0x21;
        size = (mTag->GetDataSize() - mTag->GetUnfixedInfosHmacOffset()) - 0x21;
    }

    return crypto::GenerateHMAC(mUnfixedInfosDerivedHmacKey, mTag->GetData(offset, size), hmac);
}
