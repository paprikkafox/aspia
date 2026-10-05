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

#ifndef BASE_LDAP_LDAP_MESSAGE_H
#define BASE_LDAP_LDAP_MESSAGE_H

#include <QByteArray>
#include <QList>

// LDAP protocol operation tags (APPLICATION class), RFC 4511. The value is the complete BER tag
// byte, so it can be compared with what the decoder returns.
enum class LdapOp : quint8
{
    BindRequest           = 0x60,
    BindResponse          = 0x61,
    UnbindRequest         = 0x42,
    SearchRequest         = 0x63,
    SearchResultEntry     = 0x64,
    SearchResultDone      = 0x65,
    SearchResultReference = 0x73,
    ExtendedRequest       = 0x77,
    ExtendedResponse      = 0x78
};

// Search scope, RFC 4511.
enum class LdapScope : quint8
{
    Base     = 0,
    OneLevel = 1,
    Subtree  = 2
};

// StartTLS extended-request OID, RFC 4511 section 4.14.
inline constexpr char kLdapStartTlsOid[] = "1.3.6.1.4.1.1466.20037";

// Paged results control OID, RFC 2696.
inline constexpr char kLdapPagedResultsOid[] = "1.2.840.113556.1.4.319";

// Builders return a complete LDAPMessage. The |filter| argument of a search is the BER-encoded
// Filter produced by ldapEncodeFilter().
QByteArray ldapBuildBindRequest(int message_id, const QByteArray& bind_dn, const QByteArray& password);

QByteArray ldapBuildSearchRequest(int message_id, const QByteArray& base_dn, LdapScope scope,
                                  const QByteArray& filter, const QList<QByteArray>& attributes,
                                  int size_limit = 0);

// Same as above but attaches the paged results control (RFC 2696). |cookie| is empty for the first
// page.
QByteArray ldapBuildSearchRequestPaged(int message_id, const QByteArray& base_dn, LdapScope scope,
                                       const QByteArray& filter, const QList<QByteArray>& attributes,
                                       int page_size, const QByteArray& cookie, int size_limit = 0);

QByteArray ldapBuildStartTlsRequest(int message_id);

// LDAPResult, RFC 4511 section 4.1.9.
struct LdapResult
{
    int code = -1;
    QByteArray matched_dn;
    QByteArray diagnostic;
};

struct LdapAttribute
{
    QByteArray name;
    QList<QByteArray> values;
};

struct LdapSearchEntry
{
    QByteArray object_name;
    QList<LdapAttribute> attributes;
};

// One decoded LDAPMessage. Only the fields relevant to |op| are filled.
struct LdapResponse
{
    int message_id = -1;
    LdapOp op = LdapOp::BindResponse;

    LdapResult result;
    LdapSearchEntry entry;
    QList<QByteArray> references;

    QByteArray response_name;  // ExtendedResponse [10]
    QByteArray response_value; // ExtendedResponse [11]

    // Paged results control cookie, when the response carries one.
    bool has_paged_cookie = false;
    QByteArray paged_cookie;
};

// Parses one complete LDAPMessage. Returns false on malformed input.
bool ldapParseResponse(const QByteArray& buffer, LdapResponse* response);

// Returns the number of bytes the first complete LDAPMessage occupies at the start of |buffer|.
// Returns 0 when the buffer does not yet hold a full message, and -1 when the data is malformed
// (used to frame messages on a stream socket).
qsizetype ldapMessageSize(const QByteArray& buffer);

// Human-readable name of a result code (for logs).
const char* ldapResultCodeName(int code);

#endif // BASE_LDAP_LDAP_MESSAGE_H
