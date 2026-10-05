//
// Aspia Project
// Copyright (C) 2016-2026 Dmitry Chapyshev <dmitry@aspia.ru>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//

#include "base/ldap/ldap_ber.h"

namespace {

//--------------------------------------------------------------------------------------------------
// Appends a definite length in the short form (< 0x80) or the long form.
void appendLength(QByteArray* out, qsizetype length)
{
    if (length < 0x80)
    {
        out->append(static_cast<char>(length));
        return;
    }

    char temp[sizeof(qsizetype)];
    int count = 0;

    qsizetype value = length;
    while (value > 0)
    {
        temp[count++] = static_cast<char>(value & 0xFF);
        value >>= 8;
    }

    out->append(static_cast<char>(0x80 | count));

    for (int i = count - 1; i >= 0; --i)
        out->append(temp[i]);
}

} // namespace

//--------------------------------------------------------------------------------------------------
void BerEncoder::writeElement(quint8 tag, const QByteArray& value)
{
    data_.append(static_cast<char>(tag));
    appendLength(&data_, value.size());
    data_.append(value);
}

//--------------------------------------------------------------------------------------------------
void BerEncoder::writeRaw(const QByteArray& data)
{
    data_.append(data);
}

//--------------------------------------------------------------------------------------------------
void BerEncoder::writeBoolean(bool value)
{
    const char byte = value ? static_cast<char>(0xFF) : static_cast<char>(0x00);
    writeElement(static_cast<quint8>(BerTag::Boolean), QByteArray(1, byte));
}

//--------------------------------------------------------------------------------------------------
void BerEncoder::writeInteger(qint64 value)
{
    quint8 bytes[8];

    for (int i = 7; i >= 0; --i)
    {
        bytes[i] = static_cast<quint8>(value & 0xFF);
        value >>= 8;
    }

    // Strip redundant leading bytes: a leading 0x00 whose successor has the sign bit clear, or a
    // leading 0xFF whose successor has the sign bit set. At least one byte remains.
    qsizetype start = 0;
    while (start < 7)
    {
        const quint8 current = bytes[start];
        const quint8 next = bytes[start + 1];

        if ((current == 0x00 && (next & 0x80) == 0) || (current == 0xFF && (next & 0x80) != 0))
            ++start;
        else
            break;
    }

    writeElement(static_cast<quint8>(BerTag::Integer),
                 QByteArray(reinterpret_cast<const char*>(bytes + start),
                            static_cast<qsizetype>(8 - start)));
}

//--------------------------------------------------------------------------------------------------
void BerEncoder::writeEnumerated(quint32 value)
{
    quint8 bytes[4];

    for (int i = 3; i >= 0; --i)
    {
        bytes[i] = static_cast<quint8>(value & 0xFF);
        value >>= 8;
    }

    qsizetype start = 0;
    while (start < 3 && bytes[start] == 0x00 && (bytes[start + 1] & 0x80) == 0)
        ++start;

    writeElement(static_cast<quint8>(BerTag::Enumerated),
                 QByteArray(reinterpret_cast<const char*>(bytes + start),
                            static_cast<qsizetype>(4 - start)));
}

//--------------------------------------------------------------------------------------------------
void BerEncoder::writeOctetString(const QByteArray& value)
{
    writeElement(static_cast<quint8>(BerTag::OctetString), value);
}

//--------------------------------------------------------------------------------------------------
void BerEncoder::writeNull()
{
    writeElement(static_cast<quint8>(BerTag::Null), QByteArray());
}

//--------------------------------------------------------------------------------------------------
void BerEncoder::writeContext(quint8 number, bool constructed, const QByteArray& value)
{
    quint8 tag = static_cast<quint8>(BerClass::Context);

    if (constructed)
        tag |= 0x20;

    tag |= static_cast<quint8>(number & 0x1F);

    writeElement(tag, value);
}

//--------------------------------------------------------------------------------------------------
void BerEncoder::writeSequence(const QByteArray& content)
{
    writeElement(static_cast<quint8>(BerTag::Sequence), content);
}

//--------------------------------------------------------------------------------------------------
void BerEncoder::writeSet(const QByteArray& content)
{
    writeElement(static_cast<quint8>(BerTag::Set), content);
}

//--------------------------------------------------------------------------------------------------
BerDecoder::BerDecoder(const QByteArray& data)
    : data_(data)
{
    // Nothing
}

//--------------------------------------------------------------------------------------------------
bool BerDecoder::readElement(quint8* tag)
{
    if (offset_ >= data_.size())
        return false;

    const char* bytes = data_.constData();
    qsizetype pos = offset_;

    const quint8 element_tag = static_cast<quint8>(bytes[pos++]);

    if (pos >= data_.size())
        return false;

    const quint8 first_length_byte = static_cast<quint8>(bytes[pos++]);
    qsizetype length = 0;

    if ((first_length_byte & 0x80) == 0)
    {
        length = first_length_byte;
    }
    else
    {
        const int count = first_length_byte & 0x7F;

        // Indefinite length (0x80) is not used by LDAP, and a length wider than qsizetype cannot be
        // trusted anyway.
        if (count == 0 || count > static_cast<int>(sizeof(qsizetype)))
            return false;

        if (pos + count > data_.size())
            return false;

        for (int i = 0; i < count; ++i)
            length = (length << 8) | static_cast<quint8>(bytes[pos++]);
    }

    if (length < 0 || length > data_.size() - pos)
        return false;

    value_offset_ = pos;
    value_size_ = length;
    offset_ = pos + length;

    if (tag)
        *tag = element_tag;

    return true;
}

//--------------------------------------------------------------------------------------------------
QByteArray BerDecoder::value() const
{
    return QByteArray(data_.constData() + value_offset_, value_size_);
}

//--------------------------------------------------------------------------------------------------
bool BerDecoder::toInteger(qint64* value) const
{
    if (value_size_ <= 0 || value_size_ > static_cast<qsizetype>(sizeof(qint64)))
        return false;

    const char* bytes = data_.constData() + value_offset_;

    qint64 result = (static_cast<quint8>(bytes[0]) & 0x80) ? -1 : 0;

    for (qsizetype i = 0; i < value_size_; ++i)
        result = (result << 8) | static_cast<quint8>(bytes[i]);

    *value = result;
    return true;
}

//--------------------------------------------------------------------------------------------------
bool BerDecoder::toBoolean(bool* value) const
{
    if (value_size_ != 1)
        return false;

    *value = data_[value_offset_] != 0;
    return true;
}

//--------------------------------------------------------------------------------------------------
bool BerDecoder::toOctetString(QByteArray* value) const
{
    *value = QByteArray(data_.constData() + value_offset_, value_size_);
    return true;
}
