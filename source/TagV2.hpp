#pragma once

#include <memory>
#include <span>

#include "Tag.hpp"

class TagV2 : public Tag {
public:
    TagV2();
    virtual ~TagV2();

    static std::shared_ptr<TagV2> FromBytes(const std::span<const std::byte>& data);
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
    std::size_t mOriginalFileSize;
};
