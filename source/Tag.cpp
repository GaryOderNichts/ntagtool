#include "Tag.hpp"

Tag::Tag()
 : mData()
{
}

Tag::~Tag()
{
}

bool Tag::IsEncrypted() const
{
    return mIsEncrypted;
}

void Tag::SetEncrypted(bool encrypted)
{
    mIsEncrypted = encrypted;
}

const std::array<std::byte, 540>& Tag::GetData() const
{
    return mData;
}

const std::span<const std::byte> Tag::GetData(std::size_t offset, std::size_t count) const
{
    return std::span(mData).subspan(offset, count);
}

std::array<std::byte, 540>& Tag::GetData()
{
    return mData;
}

std::span<std::byte> Tag::GetData(std::size_t offset, std::size_t count)
{
    return std::span(mData).subspan(offset, count);
}
