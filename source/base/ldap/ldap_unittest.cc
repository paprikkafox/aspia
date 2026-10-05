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
#include "base/ldap/ldap_filter.h"
#include "base/ldap/ldap_group.h"
#include "base/ldap/ldap_message.h"

#include <gtest/gtest.h>

#include <initializer_list>

namespace {

//--------------------------------------------------------------------------------------------------
QByteArray bytes(std::initializer_list<int> values)
{
    QByteArray result;
    result.reserve(static_cast<qsizetype>(values.size()));

    for (int value : values)
        result.append(static_cast<char>(value));

    return result;
}

} // namespace

//--------------------------------------------------------------------------------------------------
TEST(LdapBerTest, EncodeInteger)
{
    const auto encoded = [](qint64 value)
    {
        BerEncoder encoder;
        encoder.writeInteger(value);
        return encoder.data();
    };

    EXPECT_EQ(encoded(0), bytes({ 0x02, 0x01, 0x00 }));
    EXPECT_EQ(encoded(1), bytes({ 0x02, 0x01, 0x01 }));
    EXPECT_EQ(encoded(127), bytes({ 0x02, 0x01, 0x7F }));
    EXPECT_EQ(encoded(128), bytes({ 0x02, 0x02, 0x00, 0x80 }));
    EXPECT_EQ(encoded(255), bytes({ 0x02, 0x02, 0x00, 0xFF }));
    EXPECT_EQ(encoded(256), bytes({ 0x02, 0x02, 0x01, 0x00 }));
    EXPECT_EQ(encoded(-1), bytes({ 0x02, 0x01, 0xFF }));
    EXPECT_EQ(encoded(-128), bytes({ 0x02, 0x01, 0x80 }));
    EXPECT_EQ(encoded(-129), bytes({ 0x02, 0x02, 0xFF, 0x7F }));
}

//--------------------------------------------------------------------------------------------------
TEST(LdapBerTest, EncodeBooleanAndNull)
{
    {
        BerEncoder encoder;
        encoder.writeBoolean(true);
        EXPECT_EQ(encoder.data(), bytes({ 0x01, 0x01, 0xFF }));
    }
    {
        BerEncoder encoder;
        encoder.writeBoolean(false);
        EXPECT_EQ(encoder.data(), bytes({ 0x01, 0x01, 0x00 }));
    }
    {
        BerEncoder encoder;
        encoder.writeNull();
        EXPECT_EQ(encoder.data(), bytes({ 0x05, 0x00 }));
    }
}

//--------------------------------------------------------------------------------------------------
TEST(LdapBerTest, EncodeOctetString)
{
    BerEncoder encoder;
    encoder.writeOctetString(QByteArrayLiteral("abc"));
    EXPECT_EQ(encoder.data(), bytes({ 0x04, 0x03, 'a', 'b', 'c' }));
}

//--------------------------------------------------------------------------------------------------
TEST(LdapBerTest, EncodeSequenceAndContext)
{
    BerEncoder inner;
    inner.writeOctetString(QByteArrayLiteral("a"));

    {
        BerEncoder encoder;
        encoder.writeSequence(inner.data());
        EXPECT_EQ(encoder.data(), bytes({ 0x30, 0x03, 0x04, 0x01, 'a' }));
    }
    {
        BerEncoder encoder;
        encoder.writeContext(0, false, inner.data());
        EXPECT_EQ(encoder.data(), bytes({ 0x80, 0x03, 0x04, 0x01, 'a' }));
    }
    {
        BerEncoder encoder;
        encoder.writeContext(1, true, inner.data());
        EXPECT_EQ(encoder.data(), bytes({ 0xA1, 0x03, 0x04, 0x01, 'a' }));
    }
}

//--------------------------------------------------------------------------------------------------
TEST(LdapBerTest, EncodeLongLength)
{
    const QByteArray payload(200, 'x');

    BerEncoder encoder;
    encoder.writeOctetString(payload);

    // 200 = 0xC8 uses the long form: 0x81 0xC8.
    EXPECT_EQ(encoder.data().left(4), bytes({ 0x04, 0x81, 0xC8 }) + QByteArray(1, 'x'));
    EXPECT_EQ(encoder.data().size(), 203);
}

//--------------------------------------------------------------------------------------------------
TEST(LdapBerTest, DecodeIntegerRoundTrip)
{
    for (qint64 value : { 0LL, 1LL, -1LL, 127LL, 128LL, -129LL, 65535LL, 1000000LL })
    {
        BerEncoder encoder;
        encoder.writeInteger(value);

        BerDecoder decoder(encoder.data());

        quint8 tag = 0;
        ASSERT_TRUE(decoder.readElement(&tag));
        EXPECT_EQ(tag, static_cast<quint8>(BerTag::Integer));

        qint64 decoded = 0;
        ASSERT_TRUE(decoder.toInteger(&decoded));
        EXPECT_EQ(decoded, value);
        EXPECT_TRUE(decoder.atEnd());
    }
}

//--------------------------------------------------------------------------------------------------
TEST(LdapBerTest, DecodeSequence)
{
    BerEncoder inner;
    inner.writeInteger(1);
    inner.writeOctetString(QByteArrayLiteral("two"));

    BerEncoder outer;
    outer.writeSequence(inner.data());

    BerDecoder decoder(outer.data());

    quint8 tag = 0;
    ASSERT_TRUE(decoder.readElement(&tag));
    EXPECT_EQ(tag, static_cast<quint8>(BerTag::Sequence));

    BerDecoder sequence = decoder.nested();
    EXPECT_TRUE(decoder.atEnd());

    qint64 number = 0;
    ASSERT_TRUE(sequence.readElement(&tag));
    EXPECT_EQ(tag, static_cast<quint8>(BerTag::Integer));
    ASSERT_TRUE(sequence.toInteger(&number));
    EXPECT_EQ(number, 1);

    QByteArray text;
    ASSERT_TRUE(sequence.readElement(&tag));
    EXPECT_EQ(tag, static_cast<quint8>(BerTag::OctetString));
    ASSERT_TRUE(sequence.toOctetString(&text));
    EXPECT_EQ(text, QByteArrayLiteral("two"));

    EXPECT_TRUE(sequence.atEnd());
}

//--------------------------------------------------------------------------------------------------
TEST(LdapBerTest, DecodeRejectsMalformed)
{
    // Truncated header (tag only).
    EXPECT_FALSE(BerDecoder(bytes({ 0x04 })).readElement());

    // Truncated long-form length.
    EXPECT_FALSE(BerDecoder(bytes({ 0x04, 0x82, 0x01 })).readElement());

    // Indefinite length is not used by LDAP.
    EXPECT_FALSE(BerDecoder(bytes({ 0x30, 0x80, 0x00, 0x00 })).readElement());

    // Declared length runs past the end of the buffer.
    EXPECT_FALSE(BerDecoder(bytes({ 0x04, 0x05, 'a' })).readElement());

    // Valid element followed by a truncated one; the first read succeeds, the second fails.
    BerDecoder decoder(bytes({ 0x04, 0x01, 'a', 0x04, 0x05, 'b' }));
    ASSERT_TRUE(decoder.readElement());
    EXPECT_FALSE(decoder.readElement());
}

//--------------------------------------------------------------------------------------------------
TEST(LdapFilterTest, EscapesSpecialCharacters)
{
    EXPECT_EQ(ldapEscapeFilterValue(QByteArrayLiteral("john")), QByteArrayLiteral("john"));

    EXPECT_EQ(ldapEscapeFilterValue(QByteArrayLiteral("a*b")), QByteArrayLiteral("a\\2ab"));
    EXPECT_EQ(ldapEscapeFilterValue(QByteArrayLiteral("a(b)c")), QByteArrayLiteral("a\\28b\\29c"));
    EXPECT_EQ(ldapEscapeFilterValue(QByteArrayLiteral("a\\b")), QByteArrayLiteral("a\\5cb"));

    const QByteArray with_nul("a\0b", 3);
    EXPECT_EQ(ldapEscapeFilterValue(with_nul), QByteArrayLiteral("a\\00b"));
}

//--------------------------------------------------------------------------------------------------
TEST(LdapFilterTest, PreservesUtf8)
{
    const QString name = QString::fromUtf8("\xD0\x98\xD0\xB2\xD0\xB0\xD0\xBD");
    EXPECT_EQ(ldapEscapeFilterValue(name), name.toUtf8());
}

//--------------------------------------------------------------------------------------------------
// A distinguished name value follows the rules of RFC 4514, which differ from the filter rules.
TEST(LdapFilterTest, EscapesDnValues)
{
    EXPECT_EQ(ldapEscapeDnValue(QByteArrayLiteral("john")), QByteArrayLiteral("john"));

    EXPECT_EQ(ldapEscapeDnValue(QByteArrayLiteral("a,b")), QByteArrayLiteral("a\\,b"));
    EXPECT_EQ(ldapEscapeDnValue(QByteArrayLiteral("a+b")), QByteArrayLiteral("a\\+b"));
    EXPECT_EQ(ldapEscapeDnValue(QByteArrayLiteral("a;b")), QByteArrayLiteral("a\\;b"));
    EXPECT_EQ(ldapEscapeDnValue(QByteArrayLiteral("a<b")), QByteArrayLiteral("a\\<b"));
    EXPECT_EQ(ldapEscapeDnValue(QByteArrayLiteral("a>b")), QByteArrayLiteral("a\\>b"));
    EXPECT_EQ(ldapEscapeDnValue(QByteArrayLiteral("a\\b")), QByteArrayLiteral("a\\\\b"));
    EXPECT_EQ(ldapEscapeDnValue(QByteArrayLiteral("a\"b")), QByteArrayLiteral("a\\\"b"));

    // A leading '#' or space and a trailing space are escaped, an inner space is not.
    EXPECT_EQ(ldapEscapeDnValue(QByteArrayLiteral("#a")), QByteArrayLiteral("\\#a"));
    EXPECT_EQ(ldapEscapeDnValue(QByteArrayLiteral(" a")), QByteArrayLiteral("\\ a"));
    EXPECT_EQ(ldapEscapeDnValue(QByteArrayLiteral("a ")), QByteArrayLiteral("a\\ "));
    EXPECT_EQ(ldapEscapeDnValue(QByteArrayLiteral("a b")), QByteArrayLiteral("a b"));

    const QByteArray with_nul("a\0b", 3);
    EXPECT_EQ(ldapEscapeDnValue(with_nul), QByteArrayLiteral("a\\00b"));
}

//--------------------------------------------------------------------------------------------------
TEST(LdapFilterTest, EncodesExtensibleMatch)
{
    // The form the Active Directory matching rule in chain takes. The value is a DN and carries '='
    // and ',' itself: everything after ":=" up to the closing bracket is the value.
    QByteArray encoded;
    ASSERT_TRUE(ldapEncodeFilter(
        QByteArrayLiteral("(member:1.2.840.113556.1.4.1941:=CN=user,OU=x,DC=y)"), &encoded));

    EXPECT_EQ(encoded.toHex(), QByteArrayLiteral(
        "a934"                                        // extensibleMatch [9], 52 bytes.
        "8117" "312e322e3834302e3131333535362e312e342e31393431" // [1] matching rule.
        "8206" "6d656d626572"                          // [2] type "member".
        "8311" "434e3d757365722c4f553d782c44433d79"));  // [3] value "CN=user,OU=x,DC=y".
}

//--------------------------------------------------------------------------------------------------
// A DN with Cyrillic and spaces is a plain UTF-8 assertion value: nothing in it is special to the
// filter grammar, so the bytes go through unchanged.
TEST(LdapFilterTest, EncodesNestedGroupFilterWithCyrillicDn)
{
    const QByteArray dn =
        QByteArrayLiteral("CN=\xd0\xa2\xd0\xb5\xd1\x81\xd1\x82 \xd0\x9f\xd0\xbe\xd0\xbb\xd1\x8c\xd0\xb7\xd0\xbe\xd0\xb2\xd0\xb0\xd1\x82\xd0\xb5\xd0\xbb\xd1\x8c,"
                          "OU=\xd0\x9e\xd1\x82\xd0\xb4\xd0\xb5\xd0\xbb,"
                          "DC=example,DC=com");

    const QByteArray nested = ldapGroupMembershipFilter(dn, /* nested */ true);
    EXPECT_EQ(nested, QByteArrayLiteral("(member:1.2.840.113556.1.4.1941:=") + dn + ')');

    QByteArray encoded;
    EXPECT_TRUE(ldapEncodeFilter(nested, &encoded));

    const QByteArray direct = ldapGroupMembershipFilter(dn, /* nested */ false);
    EXPECT_EQ(direct, QByteArrayLiteral("(member=") + dn + ')');
    EXPECT_TRUE(ldapEncodeFilter(direct, &encoded));
}

//--------------------------------------------------------------------------------------------------
// A DN that does carry a character the filter grammar uses is escaped, so it cannot break out of
// the filter it is placed in.
TEST(LdapFilterTest, EscapesDnInTheGroupFilter)
{
    const QByteArray dn = QByteArrayLiteral("CN=John (ops)\\team,OU=x,DC=y");

    const QByteArray filter = ldapGroupMembershipFilter(dn, /* nested */ false);
    EXPECT_EQ(filter, QByteArrayLiteral("(member=CN=John \\28ops\\29\\5cteam,OU=x,DC=y)"));

    QByteArray encoded;
    EXPECT_TRUE(ldapEncodeFilter(filter, &encoded));
}

//--------------------------------------------------------------------------------------------------
// A mapping names a group the way the directory writes it, while the values of memberOf are DNs, so
// the name is read out of the first RDN.
TEST(LdapGroupTest, NameFromDn)
{
    EXPECT_EQ(ldapNameFromDn(QByteArrayLiteral("cn=admins,ou=groups,dc=x")), QByteArrayLiteral("admins"));
    EXPECT_EQ(ldapNameFromDn(QByteArrayLiteral("CN=Accounting,OU=Groups,DC=example,DC=com")),
              QByteArrayLiteral("Accounting"));

    // Cyrillic and spaces are the name itself.
    EXPECT_EQ(ldapNameFromDn(QByteArrayLiteral("CN=\xd0\xa2\xd0\xb5\xd1\x81\xd1\x82 "
                                                 "\xd0\x9f\xd0\xbe\xd0\xbb\xd1\x8c\xd0\xb7\xd0\xbe\xd0\xb2\xd0\xb0\xd1\x82\xd0\xb5\xd0\xbb\xd1\x8c,OU=x")),
              QByteArrayLiteral("\xd0\xa2\xd0\xb5\xd1\x81\xd1\x82 "
                                "\xd0\x9f\xd0\xbe\xd0\xbb\xd1\x8c\xd0\xb7\xd0\xbe\xd0\xb2\xd0\xb0\xd1\x82\xd0\xb5\xd0\xbb\xd1\x8c"));

    // Escapes of RFC 4514 belong to the name.
    EXPECT_EQ(ldapNameFromDn(QByteArrayLiteral("cn=Doe\\, John,ou=x")), QByteArrayLiteral("Doe, John"));
    EXPECT_EQ(ldapNameFromDn(QByteArrayLiteral("cn=a\\20b,ou=x")), QByteArrayLiteral("a b"));

    // A multi-valued RDN: the first value.
    EXPECT_EQ(ldapNameFromDn(QByteArrayLiteral("cn=a+sn=b,ou=x")), QByteArrayLiteral("a"));

    // The attribute name does not matter, and an empty DN names nothing.
    EXPECT_EQ(ldapNameFromDn(QByteArrayLiteral("ou=x")), QByteArrayLiteral("x"));
    EXPECT_TRUE(ldapNameFromDn(QByteArray()).isEmpty());
}

//--------------------------------------------------------------------------------------------------
// Active Directory hands an attribute out in ranges when an entry holds more values than a single
// response carries; the range name says where the next slice starts.
TEST(LdapGroupTest, RangedAttributeNextStart)
{
    const auto attribute = [](const QByteArray& name)
    {
        LdapAttribute result;
        result.name = name;
        result.values.append(QByteArrayLiteral("cn=a,dc=x"));
        return result;
    };

    // A plain name: everything came back at once.
    {
        const QList<LdapAttribute> attributes{ attribute(QByteArrayLiteral("memberOf")) };
        int next = -1;
        EXPECT_FALSE(ldapRangedAttributeNextStart(attributes, QByteArrayLiteral("memberOf"), &next));
    }

    // An unfinished range: the next slice starts after its end.
    {
        const QList<LdapAttribute> attributes{
            attribute(QByteArrayLiteral("memberOf;range=0-1499")) };
        int next = -1;
        EXPECT_TRUE(ldapRangedAttributeNextStart(attributes, QByteArrayLiteral("memberOf"), &next));
        EXPECT_EQ(next, 1500);
    }

    // A range that ends in '*': the last slice.
    {
        const QList<LdapAttribute> attributes{
            attribute(QByteArrayLiteral("memberOf;range=1500-*")) };
        int next = -1;
        EXPECT_FALSE(ldapRangedAttributeNextStart(attributes, QByteArrayLiteral("memberOf"), &next));
    }

    // Another attribute is not this one.
    {
        const QList<LdapAttribute> attributes{
            attribute(QByteArrayLiteral("member;range=0-1499")) };
        int next = -1;
        EXPECT_FALSE(ldapRangedAttributeNextStart(attributes, QByteArrayLiteral("memberOf"), &next));
    }
}

TEST(LdapFilterTest, EncodesEquality)
{
    QByteArray encoded;
    ASSERT_TRUE(ldapEncodeFilter(QByteArrayLiteral("(cn=John)"), &encoded));
    EXPECT_EQ(encoded, bytes({ 0xA3, 0x0A, 0x04, 0x02, 'c', 'n', 0x04, 0x04, 'J', 'o', 'h', 'n' }));
}

//--------------------------------------------------------------------------------------------------
TEST(LdapFilterTest, EncodesPresent)
{
    QByteArray encoded;
    ASSERT_TRUE(ldapEncodeFilter(QByteArrayLiteral("(cn=*)"), &encoded));
    EXPECT_EQ(encoded, bytes({ 0x87, 0x02, 'c', 'n' }));
}

//--------------------------------------------------------------------------------------------------
TEST(LdapFilterTest, EncodesSubstring)
{
    QByteArray encoded;
    ASSERT_TRUE(ldapEncodeFilter(QByteArrayLiteral("(cn=a*b)"), &encoded));
    EXPECT_EQ(encoded, bytes({ 0xA4, 0x0C, 0x04, 0x02, 'c', 'n', 0x30, 0x06,
                               0x80, 0x01, 'a', 0x82, 0x01, 'b' }));
}

//--------------------------------------------------------------------------------------------------
TEST(LdapFilterTest, EncodesAnd)
{
    QByteArray encoded;
    ASSERT_TRUE(ldapEncodeFilter(QByteArrayLiteral("(&(cn=a)(sn=b))"), &encoded));
    EXPECT_EQ(encoded, bytes({ 0xA0, 0x12,
                               0xA3, 0x07, 0x04, 0x02, 'c', 'n', 0x04, 0x01, 'a',
                               0xA3, 0x07, 0x04, 0x02, 's', 'n', 0x04, 0x01, 'b' }));
}

//--------------------------------------------------------------------------------------------------
TEST(LdapFilterTest, EncodesNot)
{
    QByteArray encoded;
    ASSERT_TRUE(ldapEncodeFilter(QByteArrayLiteral("(!(cn=a))"), &encoded));
    EXPECT_EQ(encoded, bytes({ 0xA2, 0x09, 0xA3, 0x07, 0x04, 0x02, 'c', 'n', 0x04, 0x01, 'a' }));
}

//--------------------------------------------------------------------------------------------------
TEST(LdapFilterTest, RejectsMalformed)
{
    QByteArray encoded;
    EXPECT_FALSE(ldapEncodeFilter(QByteArrayLiteral("cn=John"), &encoded));
    EXPECT_FALSE(ldapEncodeFilter(QByteArrayLiteral("(cn=John"), &encoded));
    EXPECT_FALSE(ldapEncodeFilter(QByteArrayLiteral("(cn=John)extra"), &encoded));
    EXPECT_FALSE(ldapEncodeFilter(QByteArrayLiteral("()"), &encoded));
    EXPECT_FALSE(ldapEncodeFilter(QByteArrayLiteral("(cn=Jo\\zzhn)"), &encoded));
    EXPECT_FALSE(ldapEncodeFilter(QByteArray(), &encoded));
}

namespace {

//--------------------------------------------------------------------------------------------------
QByteArray buildSearchEntryMessage(int message_id, const QByteArray& object_name,
                                   const QByteArray& attribute, const QByteArray& value)
{
    BerEncoder values;
    values.writeOctetString(value);

    BerEncoder set;
    set.writeSet(values.data());

    BerEncoder partial;
    partial.writeOctetString(attribute);
    partial.writeRaw(set.data());

    BerEncoder partial_attribute;
    partial_attribute.writeSequence(partial.data());

    BerEncoder attributes;
    attributes.writeSequence(partial_attribute.data());

    BerEncoder entry;
    entry.writeOctetString(object_name);
    entry.writeRaw(attributes.data());

    BerEncoder op;
    op.writeElement(static_cast<quint8>(LdapOp::SearchResultEntry), entry.data());

    BerEncoder body;
    body.writeInteger(message_id);
    body.writeRaw(op.data());

    BerEncoder message;
    message.writeSequence(body.data());
    return message.data();
}

//--------------------------------------------------------------------------------------------------
QByteArray buildSearchDoneMessage(int message_id, int code, const QByteArray& cookie)
{
    BerEncoder result;
    result.writeEnumerated(static_cast<quint32>(code));
    result.writeOctetString(QByteArray());
    result.writeOctetString(QByteArray());

    BerEncoder op;
    op.writeElement(static_cast<quint8>(LdapOp::SearchResultDone), result.data());

    BerEncoder paged;
    paged.writeInteger(0);
    paged.writeOctetString(cookie);

    BerEncoder paged_value;
    paged_value.writeSequence(paged.data());

    BerEncoder control_body;
    control_body.writeOctetString(QByteArray(kLdapPagedResultsOid));
    control_body.writeBoolean(true);
    control_body.writeOctetString(paged_value.data());

    BerEncoder control;
    control.writeSequence(control_body.data());

    BerEncoder controls;
    controls.writeContext(0, true, control.data());

    BerEncoder body;
    body.writeInteger(message_id);
    body.writeRaw(op.data());
    body.writeRaw(controls.data());

    BerEncoder message;
    message.writeSequence(body.data());
    return message.data();
}

} // namespace

//--------------------------------------------------------------------------------------------------
TEST(LdapMessageTest, BuildsBindRequest)
{
    const QByteArray message = ldapBuildBindRequest(1, QByteArrayLiteral("cn=admin,dc=x"),
                                                    QByteArrayLiteral("secret"));

    BerDecoder decoder(message);
    quint8 tag = 0;
    ASSERT_TRUE(decoder.readElement(&tag));
    EXPECT_EQ(tag, static_cast<quint8>(BerTag::Sequence));

    BerDecoder body = decoder.nested();
    ASSERT_TRUE(body.readElement(&tag));
    EXPECT_EQ(tag, static_cast<quint8>(BerTag::Integer));

    qint64 id = 0;
    ASSERT_TRUE(body.toInteger(&id));
    EXPECT_EQ(id, 1);

    ASSERT_TRUE(body.readElement(&tag));
    EXPECT_EQ(tag, static_cast<quint8>(LdapOp::BindRequest));
}

//--------------------------------------------------------------------------------------------------
TEST(LdapMessageTest, ParsesBindResponse)
{
    const QByteArray message = bytes({ 0x30, 0x0C, 0x02, 0x01, 0x01, 0x61, 0x07,
                                       0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00 });

    LdapResponse response;
    ASSERT_TRUE(ldapParseResponse(message, &response));
    EXPECT_EQ(response.message_id, 1);
    EXPECT_EQ(response.op, LdapOp::BindResponse);
    EXPECT_EQ(response.result.code, 0);
}

//--------------------------------------------------------------------------------------------------
TEST(LdapMessageTest, ParsesSaslErrorBindResponse)
{
    const QByteArray message = bytes({ 0x30, 0x0C, 0x02, 0x01, 0x02, 0x61, 0x07,
                                       0x0A, 0x01, 0x31, 0x04, 0x00, 0x04, 0x00 });

    LdapResponse response;
    ASSERT_TRUE(ldapParseResponse(message, &response));
    EXPECT_EQ(response.message_id, 2);
    EXPECT_EQ(response.result.code, 49); // invalidCredentials
    EXPECT_STREQ(ldapResultCodeName(response.result.code), "invalidCredentials");
}

//--------------------------------------------------------------------------------------------------
TEST(LdapMessageTest, ParsesSearchResultEntry)
{
    const QByteArray message = buildSearchEntryMessage(2, QByteArrayLiteral("cn=John,dc=x"),
                                                       QByteArrayLiteral("cn"),
                                                       QByteArrayLiteral("John"));

    LdapResponse response;
    ASSERT_TRUE(ldapParseResponse(message, &response));
    EXPECT_EQ(response.message_id, 2);
    EXPECT_EQ(response.entry.object_name, QByteArrayLiteral("cn=John,dc=x"));
    ASSERT_EQ(response.entry.attributes.size(), 1);
    EXPECT_EQ(response.entry.attributes.at(0).name, QByteArrayLiteral("cn"));
    ASSERT_EQ(response.entry.attributes.at(0).values.size(), 1);
    EXPECT_EQ(response.entry.attributes.at(0).values.at(0), QByteArrayLiteral("John"));
}

//--------------------------------------------------------------------------------------------------
TEST(LdapMessageTest, ParsesSearchDoneWithPagedCookie)
{
    const QByteArray message = buildSearchDoneMessage(3, 4, QByteArrayLiteral("abc"));

    LdapResponse response;
    ASSERT_TRUE(ldapParseResponse(message, &response));
    EXPECT_EQ(response.message_id, 3);
    EXPECT_EQ(response.op, LdapOp::SearchResultDone);
    EXPECT_EQ(response.result.code, 4);
    EXPECT_TRUE(response.has_paged_cookie);
    EXPECT_EQ(response.paged_cookie, QByteArrayLiteral("abc"));
}

//--------------------------------------------------------------------------------------------------
TEST(LdapMessageTest, BuildsStartTlsRequest)
{
    const QByteArray message = ldapBuildStartTlsRequest(5);

    BerDecoder decoder(message);
    quint8 tag = 0;
    ASSERT_TRUE(decoder.readElement(&tag));
    EXPECT_EQ(tag, static_cast<quint8>(BerTag::Sequence));

    BerDecoder body = decoder.nested();
    ASSERT_TRUE(body.readElement(&tag));

    qint64 id = 0;
    ASSERT_TRUE(body.toInteger(&id));
    EXPECT_EQ(id, 5);

    ASSERT_TRUE(body.readElement(&tag));
    EXPECT_EQ(tag, static_cast<quint8>(LdapOp::ExtendedRequest));
}

//--------------------------------------------------------------------------------------------------
TEST(LdapGroupTest, AttributeValues)
{
    QList<LdapAttribute> attributes;

    LdapAttribute member_of;
    member_of.name = QByteArrayLiteral("memberOf");
    member_of.values = { QByteArrayLiteral("cn=g1,dc=x"), QByteArrayLiteral("cn=g2,dc=x") };
    attributes.append(member_of);

    const QList<QByteArray> values = ldapAttributeValues(attributes, QByteArrayLiteral("memberof"));
    ASSERT_EQ(values.size(), 2);
    EXPECT_EQ(values.at(0), QByteArrayLiteral("cn=g1,dc=x"));
    EXPECT_EQ(values.at(1), QByteArrayLiteral("cn=g2,dc=x"));

    EXPECT_TRUE(ldapAttributeValues(attributes, QByteArrayLiteral("missing")).isEmpty());
}

//--------------------------------------------------------------------------------------------------
TEST(LdapGroupTest, MembershipFilters)
{
    EXPECT_EQ(ldapGroupMembershipFilter(QByteArrayLiteral("cn=John,dc=x"), false),
              QByteArrayLiteral("(member=cn=John,dc=x)"));
    EXPECT_EQ(ldapGroupMembershipFilter(QByteArrayLiteral("cn=John,dc=x"), true),
              QByteArrayLiteral("(member:1.2.840.113556.1.4.1941:=cn=John,dc=x)"));

    // Special characters in the DN are escaped for the filter.
    EXPECT_EQ(ldapGroupMembershipFilter(QByteArrayLiteral("cn=a*b,dc=x"), false),
              QByteArrayLiteral("(member=cn=a\\2ab,dc=x)"));
}

//--------------------------------------------------------------------------------------------------
TEST(LdapGroupTest, MembershipFiltersAreValid)
{
    QByteArray encoded;

    EXPECT_TRUE(ldapEncodeFilter(ldapGroupMembershipFilter(QByteArrayLiteral("cn=John,dc=x"), false),
                                 &encoded));
    EXPECT_TRUE(ldapEncodeFilter(ldapGroupMembershipFilter(QByteArrayLiteral("cn=John,dc=x"), true),
                                 &encoded));
}

//--------------------------------------------------------------------------------------------------
// ldapMessageSize() frames a stream: it reports the size of the first complete message, nothing while
// that message is still short, and -1 for data that cannot be a message at all.
TEST(LdapMessageTest, MessageSize)
{
    // Fewer than two bytes cannot even hold a tag and a length.
    EXPECT_EQ(ldapMessageSize(QByteArray()), 0);
    EXPECT_EQ(ldapMessageSize(bytes({ 0x30 })), 0);

    // The first byte is not a SEQUENCE.
    EXPECT_EQ(ldapMessageSize(bytes({ 0x02, 0x01, 0x00 })), -1);

    // A short-form length: SEQUENCE { INTEGER 1 } is five bytes in all and stays incomplete until the
    // last of them has arrived.
    const QByteArray short_message = bytes({ 0x30, 0x03, 0x02, 0x01, 0x01 });
    EXPECT_EQ(ldapMessageSize(short_message.left(4)), 0);
    EXPECT_EQ(ldapMessageSize(short_message), 5);

    // A long-form length: the one-byte length 200 makes a three-byte header and a 203-byte message.
    const QByteArray long_message = bytes({ 0x30, 0x81, 0xC8 }) + QByteArray(200, 'x');
    EXPECT_EQ(ldapMessageSize(bytes({ 0x30, 0x82, 0x01 })), 0); // the length bytes are not all there.
    EXPECT_EQ(ldapMessageSize(long_message.left(100)), 0);
    EXPECT_EQ(ldapMessageSize(long_message), 203);

    // A message after the first one is not counted into the first one's size.
    EXPECT_EQ(ldapMessageSize(short_message + bytes({ 0x30, 0x03, 0x02, 0x01, 0x02 })), 5);
}

//--------------------------------------------------------------------------------------------------
TEST(LdapMessageTest, BuildsSearchRequest)
{
    QByteArray filter;
    ASSERT_TRUE(ldapEncodeFilter(QByteArrayLiteral("(cn=John)"), &filter));

    const QByteArray message = ldapBuildSearchRequest(
        7, QByteArrayLiteral("dc=example,dc=com"), LdapScope::Subtree, filter,
        { QByteArrayLiteral("cn"), QByteArrayLiteral("mail") });

    BerDecoder decoder(message);
    quint8 tag = 0;
    ASSERT_TRUE(decoder.readElement(&tag));
    EXPECT_EQ(tag, static_cast<quint8>(BerTag::Sequence));

    BerDecoder body = decoder.nested();
    ASSERT_TRUE(body.readElement(&tag));
    EXPECT_EQ(tag, static_cast<quint8>(BerTag::Integer));

    qint64 id = 0;
    ASSERT_TRUE(body.toInteger(&id));
    EXPECT_EQ(id, 7);

    ASSERT_TRUE(body.readElement(&tag));
    EXPECT_EQ(tag, static_cast<quint8>(LdapOp::SearchRequest));

    BerDecoder op = body.nested();

    // baseObject
    ASSERT_TRUE(op.readElement(&tag));
    EXPECT_EQ(tag, static_cast<quint8>(BerTag::OctetString));
    QByteArray base_dn;
    ASSERT_TRUE(op.toOctetString(&base_dn));
    EXPECT_EQ(base_dn, QByteArrayLiteral("dc=example,dc=com"));

    // scope
    ASSERT_TRUE(op.readElement(&tag));
    EXPECT_EQ(tag, static_cast<quint8>(BerTag::Enumerated));
    qint64 scope = 0;
    ASSERT_TRUE(op.toInteger(&scope));
    EXPECT_EQ(scope, static_cast<qint64>(LdapScope::Subtree));

    // derefAliases, sizeLimit and timeLimit, then typesOnly.
    ASSERT_TRUE(op.readElement(&tag)); // derefAliases
    EXPECT_EQ(tag, static_cast<quint8>(BerTag::Enumerated));

    for (int i = 0; i < 2; ++i) // sizeLimit and timeLimit
    {
        ASSERT_TRUE(op.readElement(&tag));
        EXPECT_EQ(tag, static_cast<quint8>(BerTag::Integer));
    }

    ASSERT_TRUE(op.readElement(&tag)); // typesOnly
    EXPECT_EQ(tag, static_cast<quint8>(BerTag::Boolean));

    // The encoded filter is spliced in verbatim, so its bytes are present unchanged.
    EXPECT_TRUE(message.contains(filter));

    // filter, then the attribute list.
    ASSERT_TRUE(op.readElement(&tag)); // filter
    ASSERT_TRUE(op.readElement(&tag));
    EXPECT_EQ(tag, static_cast<quint8>(BerTag::Sequence));

    QList<QByteArray> attributes;
    BerDecoder attribute_list = op.nested();
    while (!attribute_list.atEnd())
    {
        ASSERT_TRUE(attribute_list.readElement(&tag));
        EXPECT_EQ(tag, static_cast<quint8>(BerTag::OctetString));

        QByteArray attribute;
        ASSERT_TRUE(attribute_list.toOctetString(&attribute));
        attributes.append(attribute);
    }

    EXPECT_EQ(attributes,
              (QList<QByteArray>{ QByteArrayLiteral("cn"), QByteArrayLiteral("mail") }));
}
