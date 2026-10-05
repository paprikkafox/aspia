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

#ifndef BASE_LDAP_LDAP_BER_H
#define BASE_LDAP_LDAP_BER_H

#include <QByteArray>

// BER class bits (the two high bits of a tag byte), RFC 4511 section 5.1.
enum class BerClass : quint8
{
    Universal   = 0x00,
    Application = 0x40,
    Context     = 0x80,
    Private     = 0xC0
};

// Universal tag numbers used by LDAP.
enum class BerTag : quint8
{
    Boolean     = 0x01,
    Integer     = 0x02,
    OctetString = 0x04,
    Null        = 0x05,
    Enumerated  = 0x0A,
    Sequence    = 0x30,
    Set         = 0x31
};

//--------------------------------------------------------------------------------------------------
// Encoder for the subset of BER that LDAP needs. All lengths are definite; LDAP never uses the
// indefinite form. Elements are appended one after another into a growing buffer; a constructed
// element is built by first encoding its children into a separate encoder and then wrapping them
// with writeSequence()/writeSet()/writeContext().
class BerEncoder
{
public:
    BerEncoder() = default;

    // Appends a complete TLV element. |tag| already includes the class and constructed bits.
    void writeElement(quint8 tag, const QByteArray& value);

    // Appends already-encoded bytes verbatim (used to splice a pre-encoded CHOICE such as a filter
    // into a constructed element).
    void writeRaw(const QByteArray& data);

    void writeBoolean(bool value);
    void writeInteger(qint64 value);
    void writeEnumerated(quint32 value);
    void writeOctetString(const QByteArray& value);
    void writeNull();
    // Context-specific element with a tag number in the range 0..30.
    void writeContext(quint8 number, bool constructed, const QByteArray& value);
    void writeSequence(const QByteArray& content);
    void writeSet(const QByteArray& content);

    [[nodiscard]] const QByteArray& data() const { return data_; }

private:
    QByteArray data_;
};

//--------------------------------------------------------------------------------------------------
// Decoder for the same subset. The decoder owns a copy of the buffer, so a nested decoder and the
// value it produces stay valid independently of the source. readElement() advances over the
// siblings of an element and nested() descends into a constructed one.
class BerDecoder
{
public:
    BerDecoder() = default;
    explicit BerDecoder(const QByteArray& data);

    // True when every element of the buffer has been consumed (or the buffer was empty).
    [[nodiscard]] bool atEnd() const { return offset_ >= data_.size(); }

    // Reads the next element header and makes its value current. Returns false on malformed input
    // (truncated header, indefinite length, length wider than the buffer, etc.).
    bool readElement(quint8* tag = nullptr);

    // The current element's value. Valid after a successful readElement().
    [[nodiscard]] QByteArray value() const;
    [[nodiscard]] bool toInteger(qint64* value) const;
    [[nodiscard]] bool toBoolean(bool* value) const;
    [[nodiscard]] bool toOctetString(QByteArray* value) const;

    // A decoder over the current element's value (for constructed elements).
    [[nodiscard]] BerDecoder nested() const { return BerDecoder(value()); }

private:
    QByteArray data_;
    qsizetype offset_ = 0;
    qsizetype value_offset_ = 0;
    qsizetype value_size_ = 0;
};

#endif // BASE_LDAP_LDAP_BER_H
