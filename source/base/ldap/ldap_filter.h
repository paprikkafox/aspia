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

#ifndef BASE_LDAP_LDAP_FILTER_H
#define BASE_LDAP_LDAP_FILTER_H

#include <QByteArray>
#include <QString>

// Escapes a value for use as an assertion value inside an LDAP search filter, per RFC 4515
// section 3: the bytes that are special to the filter grammar (\ * ( ) and NUL) are replaced with
// their \XX hexadecimal escapes. Escaping before a value is substituted into a filter template
// prevents LDAP filter injection.
QByteArray ldapEscapeFilterValue(const QByteArray& value);

// Convenience overload: the string is encoded as UTF-8 first.
QByteArray ldapEscapeFilterValue(const QString& value);

// Escapes a value for use as a relative distinguished name value (RDN) inside a distinguished name,
// per RFC 4514 section 2.4: the characters that are special to the DN grammar are backslash-escaped,
// as are a leading '#' or space and a trailing space. Used to build a DN out of user input.
QByteArray ldapEscapeDnValue(const QByteArray& value);

// Parses an RFC 4515 search filter (the textual form, e.g. "(&(objectClass=person)(uid=jdoe))") and
// encodes it into the BER form LDAP carries on the wire. Returns false and leaves |out| untouched
// on malformed input. Supports and (&), or (|), not (!), equality (=), approx (~=), >=, <=, presence
// (attr=*), substrings (attr=x*y) and extensible matching (attr:rule:=value / :dn:rule:=value).
bool ldapEncodeFilter(const QByteArray& filter, QByteArray* out);
bool ldapEncodeFilter(const QString& filter, QByteArray* out);

#endif // BASE_LDAP_LDAP_FILTER_H
