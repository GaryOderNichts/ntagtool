#include "ndef.hpp"

#include <iostream>
#include <cassert>

namespace ndef {

Record::Record()
{
}

Record::~Record()
{
}

std::optional<Record> Record::FromStream(Stream& stream)
{
    Record rec;

    // Read record header
    uint8_t recHdr;
    stream >> recHdr;
    rec.mFlags = recHdr & ~NDEF_TNF_MASK;
    rec.mTNF = static_cast<TypeNameFormat>(recHdr & NDEF_TNF_MASK);

    // Type length
    uint8_t typeLen;
    stream >> typeLen;

    // Payload length;
    uint32_t payloadLen;
    if (recHdr & NDEF_SR) {
        uint8_t len;
        stream >> len;
        payloadLen = len;
    } else {
        stream >> payloadLen;
    }

    // Some sane limits for the payload size
    if (payloadLen > 2 * 1024 * 1024) {
        return {};
    }

    // ID length
    uint8_t idLen = 0;
    if (recHdr & NDEF_IL) {
        stream >> idLen;
    }

    // Make sure we didn't read past the end of the stream yet
    if (stream.GetError() != Stream::ERROR_OK) {
        return {};
    }

    // Type
    rec.mType.resize(typeLen);
    stream.Read(rec.mType);

    // ID
    rec.mID.resize(idLen);
    stream.Read(rec.mID);

    // Payload
    rec.mPayload.resize(payloadLen);
    stream.Read(rec.mPayload);

    // Make sure we didn't read past the end of the stream again
    if (stream.GetError() != Stream::ERROR_OK) {
        return {};
    }

    return rec;
}

std::vector<std::byte> Record::ToBytes(uint8_t flags) const
{
    std::vector<std::byte> bytes;
    VectorStream stream(bytes, std::endian::big);

    // Combine flags (clear message begin and end flags)
    std::uint8_t finalFlags = mFlags & ~(NDEF_MB | NDEF_ME);
    finalFlags |= flags;

    // Write flags + tnf
    stream << std::uint8_t(finalFlags | std::uint8_t(mTNF));

    // Type length
    stream << std::uint8_t(mType.size());

    // Payload length
    if (IsShort()) {
        stream << std::uint8_t(mPayload.size());
    } else {
        stream << std::uint32_t(mPayload.size());
    }

    // ID length
    if (mFlags & NDEF_IL) {
        stream << std::uint8_t(mID.size());
    }

    // Type
    stream.Write(mType);

    // ID
    stream.Write(mID);

    // Payload
    stream.Write(mPayload);

    return bytes;
}

Record::TypeNameFormat Record::GetTNF() const
{
    return mTNF;
}

const std::vector<std::byte>& Record::GetID() const
{
    return mID;
}

const std::vector<std::byte>& Record::GetType() const
{
    return mType;
}

const std::vector<std::byte>& Record::GetPayload() const
{
    return mPayload;
}

void Record::SetTNF(TypeNameFormat tnf)
{
    mTNF = tnf;
}

void Record::SetID(const std::span<const std::byte>& id)
{
    assert(id.size() < 0x100);

    if (id.size() > 0) {
        mFlags |= NDEF_IL;
    } else {
        mFlags &= ~NDEF_IL;
    }

    mID.assign(id.begin(), id.end());
}

void Record::SetType(const std::span<const std::byte>& type)
{
    assert(type.size() < 0x100);

    mType.assign(type.begin(), type.end());
}

void Record::SetPayload(const std::span<const std::byte>& payload)
{
    // Update short record flag
    if (payload.size() < 0xff) {
        mFlags |= NDEF_SR;
    } else {
        mFlags &= ~NDEF_SR;
    }

    mPayload.assign(payload.begin(), payload.end());
}

bool Record::IsLast() const
{
    return mFlags & NDEF_ME;
}

bool Record::IsShort() const
{
    return mFlags & NDEF_SR;
}

Message::Message()
{
}

Message::~Message()
{
}

std::optional<Message> Message::FromBytes(const std::span<const std::byte>& data)
{
    Message msg;
    SpanStream stream(data, std::endian::big);

    while (stream.GetRemaining() > 0) {
        std::optional<Record> rec = Record::FromStream(stream);
        if (!rec) {
            std::cerr << "Warning: Failed to parse NDEF Record #" << msg.mRecords.size()
                << ". Ignoring the remaining " << stream.GetRemaining() << " bytes in NDEF message" << std::endl;
            break;
        }

        msg.mRecords.emplace_back(*rec);

        if ((*rec).IsLast() && stream.GetRemaining() > 0) {
            std::cerr << "Warning: Ignoring " << stream.GetRemaining() << " bytes in NDEF message" << std::endl;
            break;
        }
    }

    if (msg.mRecords.empty()) {
        return {};
    }

    if (!msg.mRecords.back().IsLast()) {
        std::cerr << "Error: NDEF message missing end record" << std::endl;
        return {}; 
    }

    return msg;
}

std::vector<std::byte> Message::ToBytes() const
{
    std::vector<std::byte> bytes;

    for (std::size_t i = 0; i < mRecords.size(); i++) {
        std::uint8_t flags = 0;

        // Add message begin flag to first record
        if (i == 0) {
            flags |= Record::NDEF_MB;
        }

        // Add message end flag to last record
        if (i == mRecords.size() - 1) {
            flags |= Record::NDEF_ME;
        }

        std::vector<std::byte> recordBytes = mRecords[i].ToBytes(flags);
        bytes.insert(bytes.end(), recordBytes.begin(), recordBytes.end());
    }

    return bytes;
}

} // namespace ndef
