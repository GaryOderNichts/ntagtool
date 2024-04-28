#pragma once

#include <cstdint>
#include <array>
#include <span>
#include <vector>

class Tag {
public:
    Tag();
    virtual ~Tag();

    bool IsEncrypted() const;
    void SetEncrypted(bool encrypted);

    virtual std::vector<std::byte> ToBytes() const = 0;

    virtual std::uint32_t GetVersion() const = 0;
    virtual std::uint32_t GetDataSize() const = 0;
    virtual std::uint32_t GetSeedOffset() const = 0;
    virtual std::uint32_t GetKeyGenSaltOffset() const = 0;
    virtual std::uint32_t GetUidOffset() const = 0;
    virtual std::uint32_t GetUnfixedInfosOffset() const = 0;
    virtual std::uint32_t GetUnfixedInfosSize() const = 0;
    virtual std::uint32_t GetLockedSecretOffset() const = 0;
    virtual std::uint32_t GetLockedSecretSize() const = 0;
    virtual std::uint32_t GetUnfixedInfosHmacOffset() const = 0;
    virtual std::uint32_t GetLockedSecretHmacOffset() const = 0;

    const std::array<std::byte, 540>& GetData() const;
    const std::span<const std::byte> GetData(std::size_t offset, std::size_t count) const;

    std::array<std::byte, 540>& GetData();
    std::span<std::byte> GetData(std::size_t offset, std::size_t count);

protected:
    bool mIsEncrypted;
    std::array<std::byte, 540> mData;
};
