#include "TagV0.hpp"
#include "TLV.hpp"
#include "ndef.hpp"

#include <iostream>
#include <algorithm>

namespace {

constexpr std::size_t kTagSize = 512u;
constexpr std::size_t kMaxBlockCount = kTagSize / sizeof(TagV0::Block);

// While these blocks are technically part of the memory control tlv, they are hardcoded in the gamepad firmware and nfc.rpl
constexpr std::uint8_t kLockbyteBlock0 = 0xe;
constexpr std::uint8_t kLockbytesStart0 = 0x0;
constexpr std::uint8_t kLockbytesEnd0 = 0x2;
constexpr std::uint8_t kLockbyteBlock1 = 0xf;
constexpr std::uint8_t kLockbytesStart1 = 0x2;
constexpr std::uint8_t kLockbytesEnd1 = 0x8;

constexpr std::uint8_t kNDEFMagicNumber = 0xe1;

// These blocks are not put into the locked area by the nfc.rpl
constexpr bool IsBlockLockedOrReserved(std::uint8_t blockIdx)
{
    // Block 0 is the UID
    if (blockIdx == 0x0) {
        return true;
    }

    // Block 0xd is reserved
    if (blockIdx == 0xd) {
        return true;
    }

    // Block 0xe and 0xf contains lock / reserved bytes
    if (blockIdx == 0xe || blockIdx == 0xf) {
        return true;
    }

    return false;
}

} // namespace

TagV0::TagV0()
 : Tag()
{
}

TagV0::~TagV0()
{
}

std::shared_ptr<TagV0> TagV0::FromBytes(const std::span<const std::byte>& data)
{
    // Version 0 tags need at least 512 bytes
    if (data.size() != kTagSize) {
        std::cerr << "Error: Version 0 tags should be " << kTagSize << " bytes in size" << std::endl;
        return {};
    }

    std::shared_ptr<TagV0> tag = std::make_shared<TagV0>();

    // Parse the locked area before continuing
    if (!tag->ParseLockedArea(data)) {
        std::cerr << "Error: Failed to parse locked area" << std::endl;
        return {};
    }

    // Now that the locked area is known, parse the data area
    std::vector<std::byte> dataArea;
    if (!tag->ParseDataArea(data, dataArea)) {
        std::cerr << "Error: Failed to parse data area" << std::endl;
        return {};
    }

    // The first few bytes in the dataArea make up the capability container
    std::copy_n(dataArea.begin(), tag->mCapabilityContainer.size(), std::as_writable_bytes(std::span(tag->mCapabilityContainer)).begin());
    if (!tag->ValidateCapabilityContainer()) {
        std::cerr << "Error: Failed to validate capability container" << std::endl;
        return {};
    }

    // The rest of the dataArea contains the TLVs
    tag->mTLVs = TLV::FromBytes(std::span(dataArea).subspan(tag->mCapabilityContainer.size()));
    if (tag->mTLVs.empty()) {
        std::cerr << "Error: Tag contains no TLVs" << std::endl;
        return {};
    }

    // Look for the NDEF tlv
    std::size_t ndefTlvIdx = static_cast<size_t>(-1);
    for (std::size_t i = 0; i < tag->mTLVs.size(); i++) {
        if (tag->mTLVs[i].GetTag() == TLV::TAG_NDEF) {
            ndefTlvIdx = i;
            break;
        }
    }

    if (ndefTlvIdx == static_cast<size_t>(-1)) {
        std::cerr << "Error: Tag contains no NDEF TLV" << std::endl;
        return {};
    }

    const TLV& ndefTlv = tag->mTLVs[ndefTlvIdx];

    // Parse the NDEF message
    std::optional<ndef::Message> ndefMessage = ndef::Message::FromBytes(ndefTlv.GetValue());
    if (!ndefMessage) {
        std::cerr << "Error: Failed to parse NDEF message" << std::endl;
        return {};
    }
    tag->mNdefMessage = *ndefMessage;

    // Look for the unknown record which contains the data ntag cares about
    std::size_t payloadSize = 0;
    for (const ndef::Record& rec : tag->mNdefMessage) {
        if (rec.GetTNF() == ndef::Record::NDEF_TNF_UNKNOWN) {
            // Copy payload to data
            payloadSize = rec.GetPayload().size();
            std::copy(rec.GetPayload().begin(), rec.GetPayload().end(), tag->GetData().begin());
            break;
        }
    }

    if (payloadSize == 0) {
        std::cerr << "Error: Tag doesn't contain NDEF payload" << std::endl;
        return {};
    }

    // Append locked data
    auto dataIterator = tag->GetData().begin() + payloadSize;
    for (const auto& [key, value] : tag->mLockedBlocks) {
        std::copy(value.begin(), value.end(), dataIterator);
        dataIterator += sizeof(Block);
    }

    // Verify the noftMagic
    char noftMagic[4];
    std::copy_n(tag->GetData().begin() + 0x20, sizeof(noftMagic), std::as_writable_bytes(std::span(noftMagic)).begin());
    if (!std::equal(noftMagic, noftMagic + sizeof(noftMagic), "NOFT")) {
        std::cerr << "Error: Tag doesn't contain NOFT magic" << std::endl;
        return {};
    }

    return tag;
}

std::vector<std::byte> TagV0::ToBytes() const
{
    // Create a copy of the ndef message
    std::size_t payloadSize = 0;
    ndef::Message ndefMessage = mNdefMessage;
    for (ndef::Record& rec : ndefMessage) {
        // Update the unknown record payload with the new data
        if (rec.GetTNF() == ndef::Record::NDEF_TNF_UNKNOWN) {
            payloadSize = rec.GetPayload().size();
            rec.SetPayload(std::span(mData).subspan(0, payloadSize));
            break;
        }
    }

    // Create a copy of the TLVs
    std::vector<TLV> tlvs = mTLVs;
    for (TLV& tlv : tlvs) {
        // Update the ndef value
        if (tlv.GetTag() == TLV::TAG_NDEF) {
            tlv.SetValue(ndefMessage.ToBytes());
            break;
        }
    }

    std::vector<std::byte> bytes(kTagSize);

    // Insert locked or reserved blocks
    for (const auto& [key, value] : mLockedOrReservedBlocks) {
        std::copy(value.begin(), value.end(), bytes.begin() + key * sizeof(Block));
    }

    // Insert locked area
    auto lockedDataIterator = mData.begin() + payloadSize;
    for (const auto& [key, value] : mLockedBlocks) {
        std::copy_n(lockedDataIterator, sizeof(Block), bytes.begin() + key * sizeof(Block));
        lockedDataIterator += sizeof(Block);
    }

    // Pack the dataArea into a linear buffer
    std::vector<std::byte> dataArea;
    const auto ccBytes = std::as_bytes(std::span(mCapabilityContainer));
    dataArea.insert(dataArea.end(), ccBytes.begin(), ccBytes.end());
    for (const TLV& tlv : tlvs) {
        const auto tlvBytes = tlv.ToBytes();
        dataArea.insert(dataArea.end(), tlvBytes.begin(), tlvBytes.end());
    }

    // Make sure the dataArea is block size aligned
    dataArea.resize((dataArea.size() + (sizeof(Block)-1)) & ~(sizeof(Block)-1));

    // The rest will be the data area
    auto dataIterator = dataArea.begin();
    for (std::uint8_t currentBlock = 0; currentBlock < kMaxBlockCount; currentBlock++) {
        // All blocks which aren't locked make up the dataArea
        if (!IsBlockLocked(currentBlock)) {
            std::copy_n(dataIterator, sizeof(Block), bytes.begin() + currentBlock * sizeof(Block));
            dataIterator += sizeof(Block);
        }
    }

    return bytes;
}

std::uint32_t TagV0::GetVersion() const
{
    // These tags, used by Rumble U, are called Version 0 in the ntag.rpl
    // They have the Format Version always set to 0 (see https://wiiubrew.org/wiki/Rumble_U_NFC_Figures#Format_Info)
    return 0;
}

std::uint32_t TagV0::GetDataSize() const
{
    // This is the total size of the data which is passed to ccr_nfc
    // It's the size of the NDEF payload and locked area
    return 0x1c8;
}

std::uint32_t TagV0::GetSeedOffset() const
{
    // This is the offset to the write counter in the NOFT Info
    // (see https://wiiubrew.org/wiki/Rumble_U_NFC_Figures#NOFT_Info)
    return 0x25;
}

std::uint32_t TagV0::GetKeyGenSaltOffset() const
{
    return 0x1a8;
}

std::uint32_t TagV0::GetUidOffset() const
{
    // This is the offset to the UID copy in the Format Info (see https://wiiubrew.org/wiki/Rumble_U_NFC_Figures#Format_Info)
    return 0x198;
}

std::uint32_t TagV0::GetUnfixedInfosOffset() const
{
    return 0x28;
}

std::uint32_t TagV0::GetUnfixedInfosSize() const
{
    return 0x120;
}

std::uint32_t TagV0::GetLockedSecretOffset() const
{
    return 0x168;
}

std::uint32_t TagV0::GetLockedSecretSize() const
{
    return 0x30;
}

std::uint32_t TagV0::GetUnfixedInfosHmacOffset() const
{
    return 0x0;
}

std::uint32_t TagV0::GetLockedSecretHmacOffset() const
{
    return 0x148;
}

bool TagV0::ParseLockedArea(const std::span<const std::byte>& data)
{
    std::uint8_t currentBlock = 0;

    // Start by parsing the first set of lock bytes
    for (std::uint8_t i = kLockbytesStart0; i < kLockbytesEnd0; i++) {
        std::uint8_t lockByte = std::uint8_t(data[kLockbyteBlock0 * sizeof(Block) + i]);

        // Iterate over the individual bits in the lock byte
        for (std::uint8_t j = 0; j < 8; j++) {
            // Is block locked?
            if (lockByte & (1u << j)) {
                Block blk;
                std::copy_n(data.begin() + currentBlock * sizeof(Block), sizeof(Block), blk.begin());

                // The lock bytes themselves are not part of the locked area
                if (!IsBlockLockedOrReserved(currentBlock)) {
                    mLockedBlocks.emplace(currentBlock, blk);
                } else {
                    mLockedOrReservedBlocks.emplace(currentBlock, blk);
                }
            }

            currentBlock++;
        }
    }

    // Parse the second set of lock bytes
    for (std::uint8_t i = kLockbytesStart1; i < kLockbytesEnd1; i++) {
        std::uint8_t lockByte = std::uint8_t(data[kLockbyteBlock1 * sizeof(Block) + i]);

        // Iterate over the individual bits in the lock byte
        for (std::uint8_t j = 0; j < 8; j++) {
            // Is block locked?
            if (lockByte & (1u << j)) {
                Block blk;
                std::copy_n(data.begin() + currentBlock * sizeof(Block), sizeof(Block), blk.begin());

                // The lock bytes themselves are not part of the locked area
                if (!IsBlockLockedOrReserved(currentBlock)) {
                    mLockedBlocks.emplace(currentBlock, blk);
                } else {
                    mLockedOrReservedBlocks.emplace(currentBlock, blk);
                }
            }

            currentBlock++;
        }
    }

    return true;
}

bool TagV0::IsBlockLocked(std::uint8_t blockIdx) const
{
    return mLockedBlocks.contains(blockIdx) || IsBlockLockedOrReserved(blockIdx);
}

bool TagV0::ParseDataArea(const std::span<const std::byte>& data, std::vector<std::byte>& dataArea)
{
    for (std::uint8_t currentBlock = 0; currentBlock < kMaxBlockCount; currentBlock++) {
        // All blocks which aren't locked make up the dataArea
        if (!IsBlockLocked(currentBlock)) {
            auto blockOffset = data.begin() + sizeof(Block) * currentBlock;
            dataArea.insert(dataArea.end(), blockOffset, blockOffset + sizeof(Block));
        }
    }

    return true;
}

bool TagV0::ValidateCapabilityContainer()
{
    std::uint8_t nmn = mCapabilityContainer[0]; // NDEF Magic Number
    std::uint8_t vno = mCapabilityContainer[1]; // Version Number
    std::uint8_t tms = mCapabilityContainer[2]; // Tag memory size

    if (nmn != kNDEFMagicNumber) {
        std::cerr << "Error: CC: Invalid NDEF Magic Number" << std::endl;
        return false;
    }

    if (vno >> 4 != 1) {
        std::cerr << "Error: CC: Invalid Version Number" << std::endl;
        return false;
    }

    if (8u * (tms + 1) < kTagSize) {
        std::cerr << "Error: CC: Incomplete tag memory size" << std::endl;
        return false;
    }

    return true;
}
