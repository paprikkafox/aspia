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

#include "base/ldap/ldap_filter.h"

#include <QList>

#include "base/ldap/ldap_ber.h"

namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

//--------------------------------------------------------------------------------------------------
int hexValue(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';

    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;

    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;

    return -1;
}

//--------------------------------------------------------------------------------------------------
// Recursive-descent parser for the RFC 4515 filter grammar. It produces the BER encoding of the
// Filter choice directly.
class FilterParser
{
public:
    explicit FilterParser(const QByteArray& data)
        : data_(data)
    {
        // Nothing
    }

    bool parse(QByteArray* out)
    {
        if (!parseFilter(out))
            return false;

        // Nothing may follow the top-level filter.
        return pos_ == data_.size();
    }

private:
    bool atEnd() const { return pos_ >= data_.size(); }
    char peek() const { return data_.at(pos_); }

    bool parseFilter(QByteArray* out)
    {
        if (atEnd() || peek() != '(')
            return false;

        ++pos_;

        if (!parseFilterComp(out))
            return false;

        if (atEnd() || peek() != ')')
            return false;

        ++pos_;
        return true;
    }

    bool parseFilterComp(QByteArray* out)
    {
        if (atEnd())
            return false;

        switch (peek())
        {
            case '&': ++pos_; return parseFilterList(0, out);
            case '|': ++pos_; return parseFilterList(1, out);
            case '!': ++pos_; return parseNot(out);
            default:  return parseItem(out);
        }
    }

    bool parseFilterList(quint8 number, QByteArray* out)
    {
        QByteArray body;
        int count = 0;

        while (!atEnd() && peek() == '(')
        {
            QByteArray child;
            if (!parseFilter(&child))
                return false;

            body += child;
            ++count;
        }

        if (count == 0)
            return false;

        BerEncoder encoder;
        encoder.writeContext(number, true, body);
        *out = encoder.data();
        return true;
    }

    bool parseNot(QByteArray* out)
    {
        QByteArray child;
        if (!parseFilter(&child))
            return false;

        BerEncoder encoder;
        encoder.writeContext(2, true, child);
        *out = encoder.data();
        return true;
    }

    bool parseItem(QByteArray* out)
    {
        QByteArray attribute;

        while (!atEnd() && peek() != '=' && peek() != '~' && peek() != '>' && peek() != '<' &&
               peek() != ':')
        {
            attribute += data_.at(pos_++);
        }

        if (!atEnd() && peek() == ':')
            return parseExtensible(attribute, out);

        if (atEnd())
            return false;

        const char op = peek();

        if (op == '=')
        {
            ++pos_;
            return parseEqual(attribute, out);
        }

        if ((op == '~' || op == '>' || op == '<') && pos_ + 1 < data_.size() && data_.at(pos_ + 1) == '=')
        {
            pos_ += 2;

            const quint8 number = (op == '~') ? 8 : (op == '>') ? 5 : 6;

            QByteArray value;
            if (!parseLiteralValue(&value))
                return false;

            BerEncoder body;
            body.writeOctetString(attribute);
            body.writeOctetString(value);

            BerEncoder filter;
            filter.writeContext(number, true, body.data());
            *out = filter.data();
            return true;
        }

        return false;
    }

    bool parseEqual(const QByteArray& attribute, QByteArray* out)
    {
        QList<QByteArray> parts;
        bool has_star = false;
        if (!parseValue(&parts, &has_star))
            return false;

        if (!has_star)
        {
            BerEncoder body;
            body.writeOctetString(attribute);
            body.writeOctetString(parts.value(0));

            BerEncoder filter;
            filter.writeContext(3, true, body.data());
            *out = filter.data();
            return true;
        }

        // The value was exactly "*": presence.
        if (parts.size() == 2 && parts.at(0).isEmpty() && parts.at(1).isEmpty())
        {
            BerEncoder filter;
            filter.writeContext(7, false, attribute);
            *out = filter.data();
            return true;
        }

        QByteArray substrings;

        const auto addSubstring = [&substrings](quint8 number, const QByteArray& value)
        {
            BerEncoder encoder;
            encoder.writeContext(number, false, value);
            substrings += encoder.data();
        };

        if (!parts.at(0).isEmpty())
            addSubstring(0, parts.at(0));

        for (qsizetype i = 1; i < parts.size() - 1; ++i)
        {
            if (!parts.at(i).isEmpty())
                addSubstring(1, parts.at(i));
        }

        if (!parts.last().isEmpty())
            addSubstring(2, parts.last());

        if (substrings.isEmpty())
        {
            // Degenerate value such as "**" without components: treat as presence.
            BerEncoder filter;
            filter.writeContext(7, false, attribute);
            *out = filter.data();
            return true;
        }

        BerEncoder body;
        body.writeOctetString(attribute);
        body.writeSequence(substrings);

        BerEncoder filter;
        filter.writeContext(4, true, body.data());
        *out = filter.data();
        return true;
    }

    bool parseExtensible(const QByteArray& attribute, QByteArray* out)
    {
        QByteArray matching_rule;
        bool dn_attributes = false;
        bool terminated = false;

        while (!atEnd() && peek() == ':')
        {
            ++pos_;

            if (!atEnd() && peek() == '=')
            {
                ++pos_;
                terminated = true;
                break;
            }

            QByteArray token;
            while (!atEnd() && peek() != ':' && peek() != '=')
                token += data_.at(pos_++);

            if (token == "dn")
                dn_attributes = true;
            else if (!token.isEmpty())
                matching_rule = token;
        }

        if (!terminated)
            return false;

        QByteArray value;
        if (!parseLiteralValue(&value))
            return false;

        BerEncoder body;
        if (!matching_rule.isEmpty())
            body.writeContext(1, false, matching_rule);
        if (!attribute.isEmpty())
            body.writeContext(2, false, attribute);
        body.writeContext(3, false, value);
        if (dn_attributes)
            body.writeContext(4, false, QByteArray(1, static_cast<char>(0xFF)));

        BerEncoder filter;
        filter.writeContext(9, true, body.data());
        *out = filter.data();
        return true;
    }

    // Reads an assertion value in which an unescaped '*' splits the value (equality/substring).
    bool parseValue(QList<QByteArray>* parts, bool* has_star)
    {
        parts->clear();
        *has_star = false;

        QByteArray current;

        while (!atEnd() && peek() != ')')
        {
            if (peek() == '(')
                return false;

            if (peek() == '\\')
            {
                if (pos_ + 2 >= data_.size())
                    return false;

                const int hi = hexValue(data_.at(pos_ + 1));
                const int lo = hexValue(data_.at(pos_ + 2));
                if (hi < 0 || lo < 0)
                    return false;

                current.append(static_cast<char>((hi << 4) | lo));
                pos_ += 3;
                continue;
            }

            if (peek() == '*')
            {
                *has_star = true;
                parts->append(current);
                current.clear();
                ++pos_;
                continue;
            }

            current.append(data_.at(pos_++));
        }

        parts->append(current);
        return true;
    }

    // Reads an assertion value in which '*' is an ordinary character.
    bool parseLiteralValue(QByteArray* out)
    {
        QByteArray current;

        while (!atEnd() && peek() != ')')
        {
            if (peek() == '(')
                return false;

            if (peek() == '\\')
            {
                if (pos_ + 2 >= data_.size())
                    return false;

                const int hi = hexValue(data_.at(pos_ + 1));
                const int lo = hexValue(data_.at(pos_ + 2));
                if (hi < 0 || lo < 0)
                    return false;

                current.append(static_cast<char>((hi << 4) | lo));
                pos_ += 3;
                continue;
            }

            current.append(data_.at(pos_++));
        }

        *out = current;
        return true;
    }

    const QByteArray& data_;
    qsizetype pos_ = 0;
};

} // namespace

//--------------------------------------------------------------------------------------------------
QByteArray ldapEscapeFilterValue(const QByteArray& value)
{
    QByteArray result;
    result.reserve(value.size());

    for (char ch : value)
    {
        const quint8 byte = static_cast<quint8>(ch);

        switch (byte)
        {
            case '\\':
            case '*':
            case '(':
            case ')':
            case 0x00:
            {
                result.append('\\');
                result.append(kHexDigits[(byte >> 4) & 0x0F]);
                result.append(kHexDigits[byte & 0x0F]);
            }
            break;

            default:
                result.append(ch);
                break;
        }
    }

    return result;
}

//--------------------------------------------------------------------------------------------------
QByteArray ldapEscapeFilterValue(const QString& value)
{
    return ldapEscapeFilterValue(value.toUtf8());
}

//--------------------------------------------------------------------------------------------------
bool ldapEncodeFilter(const QByteArray& filter, QByteArray* out)
{
    if (filter.isEmpty())
        return false;

    QByteArray encoded;
    if (!FilterParser(filter).parse(&encoded))
        return false;

    *out = encoded;
    return true;
}

//--------------------------------------------------------------------------------------------------
bool ldapEncodeFilter(const QString& filter, QByteArray* out)
{
    return ldapEncodeFilter(filter.toUtf8(), out);
}

//--------------------------------------------------------------------------------------------------
QByteArray ldapEscapeDnValue(const QByteArray& value)
{
    QByteArray result;
    result.reserve(value.size() * 2);

    for (qsizetype i = 0; i < value.size(); ++i)
    {
        const char character = value.at(i);
        const bool is_first = (i == 0);
        const bool is_last = (i == value.size() - 1);

        switch (character)
        {
            case '"':
            case '+':
            case ',':
            case ';':
            case '<':
            case '>':
            case '\\':
                result.append('\\');
                result.append(character);
                break;

            case '#':
                if (is_first)
                    result.append('\\');
                result.append(character);
                break;

            case ' ':
                if (is_first || is_last)
                    result.append('\\');
                result.append(character);
                break;

            case '\0':
                result.append("\\00", 3);
                break;

            default:
                result.append(character);
                break;
        }
    }

    return result;
}
