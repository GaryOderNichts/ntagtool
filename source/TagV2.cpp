#include "TagV2.hpp"

#include <iostream>
#include <algorithm>

namespace {

// Excluding pwd and reserved data
constexpr std::size_t kTagSize0 = 0x214u;
// Including pwd and reserved data
constexpr std::size_t kTagSize1 = 0x21cu;
// Amiibo Magic
constexpr std::uint8_t kTagMagic = 0xa5;

}

TagV2::TagV2()
 : Tag()
{
}

TagV2::~TagV2()
{
}

std::shared_ptr<TagV2> TagV2::FromBytes(const std::span<const std::byte>& data)
{
    if (data.size() != kTagSize0 && data.size() != kTagSize1) {
        std::cerr << "Error: Version 2 tags should be at either " << kTagSize0 << " or " << kTagSize1 << " bytes in size" << std::endl;
        return {};
    }

    // Check for the amiibo magic
    if (data[0x10] != std::byte(kTagMagic)) {
        std::cerr << "Error: Version 2 tag doesn't contain tag magic. Not a valid tag?" << std::endl;
        return {};
    }

    std::shared_ptr<TagV2> tag = std::make_shared<TagV2>();

    // Keep track of the original file size
    tag->mOriginalFileSize = data.size();

    // Convert data to internal layout
    std::copy_n(data.begin(), 8, tag->mData.begin() + tag->GetUidOffset());
    std::copy_n(data.begin() + 8, 8, tag->mData.begin());
    std::copy_n(data.begin() + 0x10, 4, tag->mData.begin() + 0x28);
    std::copy_n(data.begin() + 0x14, 0x20, tag->mData.begin() + tag->GetUnfixedInfosOffset());
    std::copy_n(data.begin() + 0x34, 0x20, tag->mData.begin() + tag->GetLockedSecretHmacOffset());
    std::copy_n(data.begin() + 0x54, 0xc, tag->mData.begin() + tag->GetLockedSecretOffset());
    std::copy_n(data.begin() + 0x60, 0x20, tag->mData.begin() + tag->GetKeyGenSaltOffset());
    std::copy_n(data.begin() + 0x80, 0x20, tag->mData.begin() + tag->GetUnfixedInfosHmacOffset());
    std::copy_n(data.begin() + 0xa0, 0x168, tag->mData.begin() + tag->GetUnfixedInfosOffset() + 0x20);

    if (data.size() ==  kTagSize1) {
        std::copy_n(data.begin() + 0x208, 0x14, tag->mData.begin() + 0x208);
    } else {
        std::copy_n(data.begin() + 0x208, 0xc, tag->mData.begin() + 0x208);
    }

    return tag;
}

std::vector<std::byte> TagV2::ToBytes() const
{
    std::vector<std::byte> bytes(mOriginalFileSize);

    // Convert internal layout back to tag data
    std::copy_n(mData.begin(), 8, bytes.begin() + 8);
    std::copy_n(mData.begin() + GetUnfixedInfosHmacOffset(), 0x20, bytes.begin() + 0x80);
    std::copy_n(mData.begin() + 0x28, 4, bytes.begin() + 0x10);
    std::copy_n(mData.begin() + GetUnfixedInfosOffset(), 0x20, bytes.begin() + 0x14);
    std::copy_n(mData.begin() + GetUnfixedInfosOffset() + 0x20, 0x168, bytes.begin() + 0xa0);
    std::copy_n(mData.begin() + GetLockedSecretHmacOffset(), 0x20, bytes.begin() + 0x34);
    std::copy_n(mData.begin() + GetUidOffset(), 8, bytes.begin());
    std::copy_n(mData.begin() + GetLockedSecretOffset(), 0xc, bytes.begin() + 0x54);
    std::copy_n(mData.begin() + GetKeyGenSaltOffset(), 0x20, bytes.begin() + 0x60);

    if (mOriginalFileSize == kTagSize1) {
        std::copy_n(mData.begin() + 0x208, 0x14, bytes.begin() + 0x208);
    } else {
        std::copy_n(mData.begin() + 0x208, 0xc, bytes.begin() + 0x208);
    }

    return bytes;
}

std::uint32_t TagV2::GetVersion() const
{
    // These tags, used as amiibo, are version 2 tags
    // They have the format version always set to 2 (see <https://www.3dbrew.org/wiki/Amiibo#Structure_of_Amiibo_Identification_Block>)
    return 2;
}

std::uint32_t TagV2::GetDataSize() const
{
    // This is the size of the tag data excluding the lock- and CFG- bytes
    return 0x208;
}

std::uint32_t TagV2::GetSeedOffset() const
{
    // This is the offset into the internal buffer which contains the write counter (offset 0x11 into raw tag data)
    return 0x29;
}

std::uint32_t TagV2::GetKeyGenSaltOffset() const
{
    // This is the offset into the internal buffer which is used to generate the key gen salt
    return 0x1e8;
}

std::uint32_t TagV2::GetUidOffset() const
{
    // This is where the 8-byte UID is stored in the internal buffer layout
    return 0x1d4;
}

std::uint32_t TagV2::GetUnfixedInfosOffset() const
{
    return 0x2c;
}

std::uint32_t TagV2::GetUnfixedInfosSize() const
{
    return 0x188;
}

std::uint32_t TagV2::GetLockedSecretOffset() const
{
    return 0x1dc;
}

std::uint32_t TagV2::GetLockedSecretSize() const
{
    // This doesn't matter since the locked secret area isn't encrypted on version 2 tags
    return 0x0;
}

std::uint32_t TagV2::GetUnfixedInfosHmacOffset() const
{
    return 0x8;
}

std::uint32_t TagV2::GetLockedSecretHmacOffset() const
{
    return 0x1b4;
}
