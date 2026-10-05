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

#include "base/ldap/ldap_message.h"

#include "base/ldap/ldap_ber.h"

namespace {

//--------------------------------------------------------------------------------------------------
// Wraps an already-encoded protocolOp into an LDAPMessage, appending optional controls.
QByteArray wrapMessage(int message_id, const QByteArray& op, const QByteArray& controls)
{
    BerEncoder body;
    body.writeInteger(message_id);

    QByteArray content = body.data();
    content += op;

    if (!controls.isEmpty())
    {
        BerEncoder controls_encoder;
        controls_encoder.writeContext(0, true, controls);
        content += controls_encoder.data();
    }

    BerEncoder message;
    message.writeSequence(content);
    return message.data();
}

//--------------------------------------------------------------------------------------------------
QByteArray buildSearchBody(const QByteArray& base_dn, LdapScope scope, const QByteArray& filter,
                           const QList<QByteArray>& attributes, int size_limit)
{
    BerEncoder content;
    content.writeOctetString(base_dn);
    content.writeEnumerated(static_cast<quint32>(scope));
    content.writeEnumerated(0); // derefAliases: neverDerefAliases.
    content.writeInteger(size_limit);
    content.writeInteger(0); // timeLimit: no limit.
    content.writeBoolean(false); // typesOnly.
    content.writeRaw(filter);

    BerEncoder attribute_list;
    for (const QByteArray& attribute : attributes)
        attribute_list.writeOctetString(attribute);

    content.writeSequence(attribute_list.data());

    BerEncoder op;
    op.writeElement(static_cast<quint8>(LdapOp::SearchRequest), content.data());
    return op.data();
}

//--------------------------------------------------------------------------------------------------
bool parseResult(BerDecoder& decoder, LdapResult* result)
{
    quint8 tag = 0;

    if (!decoder.readElement(&tag) || tag != static_cast<quint8>(BerTag::Enumerated))
        return false;

    qint64 code = 0;
    if (!decoder.toInteger(&code))
        return false;
    result->code = static_cast<int>(code);

    if (!decoder.readElement(&tag) || tag != static_cast<quint8>(BerTag::OctetString))
        return false;
    if (!decoder.toOctetString(&result->matched_dn))
        return false;

    if (!decoder.readElement(&tag) || tag != static_cast<quint8>(BerTag::OctetString))
        return false;
    if (!decoder.toOctetString(&result->diagnostic))
        return false;

    return true;
}

//--------------------------------------------------------------------------------------------------
bool parseSearchEntry(BerDecoder& decoder, LdapSearchEntry* entry)
{
    quint8 tag = 0;

    if (!decoder.readElement(&tag) || tag != static_cast<quint8>(BerTag::OctetString))
        return false;
    if (!decoder.toOctetString(&entry->object_name))
        return false;

    if (!decoder.readElement(&tag) || tag != static_cast<quint8>(BerTag::Sequence))
        return false;

    BerDecoder attributes = decoder.nested();

    while (!attributes.atEnd())
    {
        if (!attributes.readElement(&tag) || tag != static_cast<quint8>(BerTag::Sequence))
            return false;

        BerDecoder attribute = attributes.nested();

        LdapAttribute parsed;

        if (!attribute.readElement(&tag) || tag != static_cast<quint8>(BerTag::OctetString))
            return false;
        if (!attribute.toOctetString(&parsed.name))
            return false;

        if (!attribute.readElement(&tag) || tag != static_cast<quint8>(BerTag::Set))
            return false;

        BerDecoder values = attribute.nested();
        while (!values.atEnd())
        {
            quint8 value_tag = 0;
            if (!values.readElement(&value_tag))
                return false;

            QByteArray value;
            if (!values.toOctetString(&value))
                return false;

            parsed.values.append(value);
        }

        entry->attributes.append(parsed);
    }

    return true;
}

//--------------------------------------------------------------------------------------------------
bool parseReferences(BerDecoder& decoder, QList<QByteArray>* references)
{
    while (!decoder.atEnd())
    {
        quint8 tag = 0;
        if (!decoder.readElement(&tag))
            return false;

        QByteArray uri;
        if (!decoder.toOctetString(&uri))
            return false;

        references->append(uri);
    }

    return true;
}

//--------------------------------------------------------------------------------------------------
void parseControls(BerDecoder decoder, LdapResponse* response)
{
    quint8 tag = 0;

    while (!decoder.atEnd())
    {
        if (!decoder.readElement(&tag) || tag != static_cast<quint8>(BerTag::Sequence))
            return;

        BerDecoder control = decoder.nested();

        QByteArray oid;
        if (!control.readElement(&tag) || tag != static_cast<quint8>(BerTag::OctetString))
            return;
        if (!control.toOctetString(&oid))
            return;

        QByteArray value;
        bool has_value = false;

        while (!control.atEnd())
        {
            if (!control.readElement(&tag))
                return;

            if (tag == static_cast<quint8>(BerTag::OctetString))
            {
                if (!control.toOctetString(&value))
                    return;
                has_value = true;
            }
        }

        if (has_value && oid == QByteArray(kLdapPagedResultsOid))
        {
            // The value is SEQUENCE { size INTEGER, cookie OCTET STRING }.
            BerDecoder paged(value);
            if (paged.readElement(&tag) && tag == static_cast<quint8>(BerTag::Sequence))
            {
                BerDecoder inner = paged.nested();
                if (inner.readElement(&tag)) // size
                {
                    if (inner.readElement(&tag)) // cookie
                    {
                        QByteArray cookie;
                        if (inner.toOctetString(&cookie))
                        {
                            response->paged_cookie = cookie;
                            response->has_paged_cookie = true;
                        }
                    }
                }
            }
        }
    }
}

} // namespace

//--------------------------------------------------------------------------------------------------
QByteArray ldapBuildBindRequest(int message_id, const QByteArray& bind_dn, const QByteArray& password)
{
    BerEncoder bind;
    bind.writeInteger(3); // LDAP version 3.
    bind.writeOctetString(bind_dn);
    bind.writeContext(0, false, password); // simple authentication.

    BerEncoder op;
    op.writeElement(static_cast<quint8>(LdapOp::BindRequest), bind.data());

    return wrapMessage(message_id, op.data(), QByteArray());
}

//--------------------------------------------------------------------------------------------------
QByteArray ldapBuildSearchRequest(int message_id, const QByteArray& base_dn, LdapScope scope,
                                  const QByteArray& filter, const QList<QByteArray>& attributes,
                                  int size_limit)
{
    return wrapMessage(message_id, buildSearchBody(base_dn, scope, filter, attributes, size_limit),
                       QByteArray());
}

//--------------------------------------------------------------------------------------------------
QByteArray ldapBuildSearchRequestPaged(int message_id, const QByteArray& base_dn, LdapScope scope,
                                       const QByteArray& filter, const QList<QByteArray>& attributes,
                                       int page_size, const QByteArray& cookie, int size_limit)
{
    BerEncoder paged;
    paged.writeInteger(page_size);
    paged.writeOctetString(cookie);

    BerEncoder paged_value;
    paged_value.writeSequence(paged.data());

    BerEncoder control_body;
    control_body.writeOctetString(QByteArray(kLdapPagedResultsOid));
    // The control is marked non-critical, so a directory that does not know it ignores it and
    // answers without paging instead of failing the whole search with unavailableCriticalExtension.
    control_body.writeBoolean(false);
    control_body.writeOctetString(paged_value.data());

    BerEncoder control;
    control.writeSequence(control_body.data());

    return wrapMessage(message_id, buildSearchBody(base_dn, scope, filter, attributes, size_limit),
                       control.data());
}

//--------------------------------------------------------------------------------------------------
QByteArray ldapBuildStartTlsRequest(int message_id)
{
    BerEncoder request;
    request.writeContext(0, false, QByteArray(kLdapStartTlsOid)); // requestName [0]

    BerEncoder op;
    op.writeElement(static_cast<quint8>(LdapOp::ExtendedRequest), request.data());

    return wrapMessage(message_id, op.data(), QByteArray());
}

//--------------------------------------------------------------------------------------------------
bool ldapParseResponse(const QByteArray& buffer, LdapResponse* response)
{
    BerDecoder decoder(buffer);

    quint8 tag = 0;
    if (!decoder.readElement(&tag) || tag != static_cast<quint8>(BerTag::Sequence))
        return false;

    BerDecoder message = decoder.nested();

    qint64 message_id = 0;
    if (!message.readElement(&tag) || tag != static_cast<quint8>(BerTag::Integer))
        return false;
    if (!message.toInteger(&message_id))
        return false;
    response->message_id = static_cast<int>(message_id);

    if (!message.readElement(&tag))
        return false;

    const LdapOp op = static_cast<LdapOp>(tag);
    response->op = op;

    BerDecoder op_decoder = message.nested();

    switch (op)
    {
        case LdapOp::BindResponse:
        case LdapOp::SearchResultDone:
            if (!parseResult(op_decoder, &response->result))
                return false;
            break;

        case LdapOp::ExtendedResponse:
        {
            if (!parseResult(op_decoder, &response->result))
                return false;

            quint8 field_tag = 0;
            while (!op_decoder.atEnd())
            {
                if (!op_decoder.readElement(&field_tag))
                    return false;

                if (field_tag == (static_cast<quint8>(BerClass::Context) | 10))
                {
                    if (!op_decoder.toOctetString(&response->response_name))
                        return false;
                }
                else if (field_tag == (static_cast<quint8>(BerClass::Context) | 11))
                {
                    if (!op_decoder.toOctetString(&response->response_value))
                        return false;
                }
            }
            break;
        }

        case LdapOp::SearchResultEntry:
            if (!parseSearchEntry(op_decoder, &response->entry))
                return false;
            break;

        case LdapOp::SearchResultReference:
            if (!parseReferences(op_decoder, &response->references))
                return false;
            break;

        default:
            return false;
    }

    if (!message.atEnd())
    {
        quint8 controls_tag = 0;
        if (!message.readElement(&controls_tag))
            return false;

        if (static_cast<quint8>(controls_tag & 0xC0) == static_cast<quint8>(BerClass::Context)) // controls [0]
            parseControls(message.nested(), response);
    }

    return true;
}

//--------------------------------------------------------------------------------------------------
qsizetype ldapMessageSize(const QByteArray& buffer)
{
    if (buffer.size() < 2)
        return 0;

    if (static_cast<quint8>(buffer.at(0)) != static_cast<quint8>(BerTag::Sequence))
        return -1;

    const quint8 first_length_byte = static_cast<quint8>(buffer.at(1));
    qsizetype header_size = 2;
    qsizetype length = 0;

    if ((first_length_byte & 0x80) == 0)
    {
        length = first_length_byte;
    }
    else
    {
        const int count = first_length_byte & 0x7F;
        if (count == 0 || count > static_cast<int>(sizeof(qsizetype)))
            return -1;

        if (buffer.size() < 2 + count)
            return 0;

        for (int i = 0; i < count; ++i)
            length = (length << 8) | static_cast<quint8>(buffer.at(2 + i));

        header_size = 2 + count;
    }

    if (length < 0)
        return -1;

    const qsizetype message_size = header_size + length;
    if (buffer.size() < message_size)
        return 0;

    return message_size;
}

//--------------------------------------------------------------------------------------------------
const char* ldapResultCodeName(int code)
{
    switch (code)
    {
        case 0:  return "success";
        case 1:  return "operationsError";
        case 2:  return "protocolError";
        case 3:  return "timeLimitExceeded";
        case 4:  return "sizeLimitExceeded";
        case 7:  return "authMethodNotSupported";
        case 8:  return "strongerAuthRequired";
        case 10: return "referral";
        case 11: return "adminLimitExceeded";
        case 12: return "unavailableCriticalExtension";
        case 13: return "confidentialityRequired";
        case 14: return "saslBindInProgress";
        case 16: return "noSuchAttribute";
        case 17: return "undefinedAttributeType";
        case 18: return "inappropriateMatching";
        case 19: return "constraintViolation";
        case 20: return "attributeOrValueExists";
        case 21: return "invalidAttributeSyntax";
        case 32: return "noSuchObject";
        case 34: return "invalidDNSyntax";
        case 36: return "aliasDereferencingProblem";
        case 48: return "inappropriateAuthentication";
        case 49: return "invalidCredentials";
        case 50: return "insufficientAccessRights";
        case 51: return "busy";
        case 52: return "unavailable";
        case 53: return "unwillingToPerform";
        case 54: return "loopDetect";
        case 64: return "namingViolation";
        case 65: return "objectClassViolation";
        case 66: return "notAllowedOnNonLeaf";
        case 67: return "notAllowedOnRDN";
        case 68: return "entryAlreadyExists";
        case 80: return "other";
        default: return "unknown";
    }
}
