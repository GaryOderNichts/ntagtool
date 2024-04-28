#include "TLV.hpp"
#include "stream.hpp"

#include <iostream>
#include <cassert>

TLV::TLV()
{
}

TLV::TLV(Tag tag, std::vector<std::byte> value)
 : mTag(tag), mValue(std::move(value))
{
}

TLV::~TLV()
{
}

std::vector<TLV> TLV::FromBytes(const std::span<std::byte>& data)
{
    bool hasTerminator = false;
    std::vector<TLV> tlvs;
    SpanStream stream(data, std::endian::big);

    while (stream.GetRemaining() > 0 && !hasTerminator) {
        // Read the tag
        uint8_t byte;
        stream >> byte;
        Tag tag = static_cast<Tag>(byte);

        switch (tag)
        {
            case TLV::TAG_NULL:
                // Don't need to do anything for NULL tags
                break;
            
            case TLV::TAG_TERMINATOR:
                tlvs.emplace_back(tag, std::vector<std::byte>{});
                hasTerminator = true;
                break;

            default: {
                // Read the length
                uint16_t length;
                stream >> byte;
                length = byte;

                // If the length is 0xff, 2 bytes with length follow
                if (length == 0xff) {
                    stream >> length;
                }

                std::vector<std::byte> value;
                value.resize(length);
                stream.Read(value);

                tlvs.emplace_back(tag, value);
                break;
            }
        }

        if (stream.GetError() != Stream::ERROR_OK) {
            std::cerr << "Error: TLV parsing read past end of stream" << std::endl;
            // Clear tlvs to prevent further havoc while parsing ndef data
            tlvs.clear();
            break;
        }
    }

    // This seems to be okay, at least NTAGs don't add a terminator tag
    // if (!hasTerminator) {
    //     std::cerr << "Warning: TLV parsing reached end of stream without terminator tag" << std::endl;
    // }

    return tlvs;
}

std::vector<std::byte> TLV::ToBytes() const
{
    std::vector<std::byte> bytes;
    VectorStream stream(bytes, std::endian::big);

    // Write tag
    stream << std::uint8_t(mTag);

    switch (mTag)
    {
        case TLV::TAG_NULL:
        case TLV::TAG_TERMINATOR:
            // Nothing to do here
            break;

        default: {
            // Write length (decide if as a 8-bit or 16-bit value)
            if (mValue.size() >= 0xff) {
                stream << std::uint8_t(0xff);
                stream << std::uint16_t(mValue.size());
            } else {
                stream << std::uint8_t(mValue.size());
            }

            // Write value
            stream.Write(mValue);
        }
    }

    return bytes;
}

TLV::Tag TLV::GetTag() const
{
    return mTag;
}

const std::vector<std::byte>& TLV::GetValue() const
{
    return mValue;
}

void TLV::SetTag(Tag tag)
{
    mTag = tag;
}

void TLV::SetValue(const std::span<const std::byte>& value)
{
    // Can only write max 16-bit lengths into TLV
    assert(value.size() < 0x10000);

    mValue.assign(value.begin(), value.end());
}
