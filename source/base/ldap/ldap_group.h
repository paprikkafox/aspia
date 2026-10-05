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

#ifndef BASE_LDAP_LDAP_GROUP_H
#define BASE_LDAP_LDAP_GROUP_H

#include <QByteArray>
#include <QList>

#include "base/ldap/ldap_message.h"

// Active Directory matching rule that resolves group membership through nested groups, RFC 4511
// extensible matching: (member:1.2.840.113556.1.4.1941:=<user DN>).
inline constexpr char kLdapAdMatchingRuleInChain[] = "1.2.840.113556.1.4.1941";

// Returns every value of |attribute| (name compared case-insensitively) across |attributes|. The
// list is empty when the attribute is absent.
QList<QByteArray> ldapAttributeValues(const QList<LdapAttribute>& attributes,
                                      const QByteArray& attribute);

// Builds the RFC 4515 filter that selects the groups a user belongs to:
//   nested = true  -> Active Directory recursive membership (matching rule in chain), which returns
//                     every group the user belongs to, directly or through nested groups;
//   nested = false -> direct membership "(member=<user DN>)", for directories without that rule: the
//                     caller recurses into the returned group DNs to reach nested groups.
// The user DN is escaped for use as a filter assertion value.
QByteArray ldapGroupMembershipFilter(const QByteArray& user_dn, bool nested);

// The name a group is known by, taken out of its distinguished name: the value of the first RDN,
// with the escapes of RFC 4514 resolved ("CN=Doe\\, John,OU=x" gives "Doe, John"). An empty
// array is returned when the name cannot be read out of |dn|. Used for the values of memberOf, which
// are DNs, so that a mapping can name a group the way it is written in the directory.
QByteArray ldapNameFromDn(const QByteArray& dn);

// Active Directory hands out an attribute in ranges when an entry holds more values than a single
// response can carry: the first answer names it "memberOf;range=0-1499", and the rest is asked for as
// "memberOf;range=1500-*". Returns true when |attributes| holds an unfinished ranged form of
// |attribute| and sets |*next_start| to the first index still to be fetched. A plain name, or a range
// whose end is '*', means the whole attribute has been read, and returns false.
bool ldapRangedAttributeNextStart(const QList<LdapAttribute>& attributes, const QByteArray& attribute,
                                  int* next_start);

#endif // BASE_LDAP_LDAP_GROUP_H
