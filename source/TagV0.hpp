#pragma once

#include <memory>
#include <span>
#include <map>

#include "Tag.hpp"
#include "TLV.hpp"
#include "ndef.hpp"

class TagV0 : public Tag {
public:
    using Block = std::array<std::byte, 0x8>;

public:
    TagV0();
    virtual ~TagV0();

    static std::shared_ptr<TagV0> FromBytes(const std::span<const std::byte>& data);
    virtual std::vector<std::byte> ToBytes() const override;

    virtual std::uint32_t GetVersion() const override;
    virtual std::uint32_t GetDataSize() const override;
    virtual std::uint32_t GetSeedOffset() const override;
    virtual std::uint32_t GetKeyGenSaltOffset() const override;
    virtual std::uint32_t GetUidOffset() const override;
    virtual std::uint32_t GetUnfixedInfosOffset() const override;
    virtual std::uint32_t GetUnfixedInfosSize() const override;
    virtual std::uint32_t GetLockedSecretOffset() const override;
    virtual std::uint32_t GetLockedSecretSize() const override;
    virtual std::uint32_t GetUnfixedInfosHmacOffset() const override;
    virtual std::uint32_t GetLockedSecretHmacOffset() const override;

private:
    bool ParseLockedArea(const std::span<const std::byte>& data);
    bool IsBlockLocked(std::uint8_t blockIdx) const;
    bool ParseDataArea(const std::span<const std::byte>& data, std::vector<std::byte>& dataArea);
    bool ValidateCapabilityContainer();

    std::map<std::uint8_t, Block> mLockedOrReservedBlocks;
    std::map<std::uint8_t, Block> mLockedBlocks;
    std::array<std::uint8_t, 0x4> mCapabilityContainer;
    std::vector<TLV> mTLVs;
    ndef::Message mNdefMessage;
};
