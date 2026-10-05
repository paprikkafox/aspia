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

#include "base/ldap/ldap_group.h"

#include "base/ldap/ldap_filter.h"

//--------------------------------------------------------------------------------------------------
QList<QByteArray> ldapAttributeValues(const QList<LdapAttribute>& attributes,
                                      const QByteArray& attribute)
{
    QList<QByteArray> result;

    for (const LdapAttribute& entry : attributes)
    {
        // A name can carry options after a ';'. Active Directory uses them: a user in more groups
        // than one response carries comes back with "memberOf;range=0-1499", and asking for
        // "memberOf" alone would match nothing. The name is compared without its options.
        const qsizetype separator = entry.name.indexOf(';');
        const QByteArray name = (separator < 0) ? entry.name : entry.name.left(separator);

        if (name.compare(attribute, Qt::CaseInsensitive) == 0)
            result.append(entry.values);
    }

    return result;
}

//--------------------------------------------------------------------------------------------------
QByteArray ldapGroupMembershipFilter(const QByteArray& user_dn, bool nested)
{
    const QByteArray value = ldapEscapeFilterValue(user_dn);

    if (nested)
        return "(member:" + QByteArray(kLdapAdMatchingRuleInChain) + ":=" + value + ")";

    return "(member=" + value + ")";
}

namespace {

//--------------------------------------------------------------------------------------------------
int hexDigit(char character)
{
    if (character >= '0' && character <= '9')
        return character - '0';
    if (character >= 'a' && character <= 'f')
        return character - 'a' + 10;
    if (character >= 'A' && character <= 'F')
        return character - 'A' + 10;

    return -1;
}

} // namespace

//--------------------------------------------------------------------------------------------------
bool ldapRangedAttributeNextStart(const QList<LdapAttribute>& attributes, const QByteArray& attribute,
                                  int* next_start)
{
    for (const LdapAttribute& entry : attributes)
    {
        const qsizetype separator = entry.name.indexOf(';');
        const QByteArray name = (separator < 0) ? entry.name : entry.name.left(separator);

        if (name.compare(attribute, Qt::CaseInsensitive) != 0)
            continue;

        // A plain name is the whole attribute; there is nothing left to ask for.
        if (separator < 0)
            continue;

        const QByteArray options = entry.name.mid(separator + 1);
        const int range_position = options.indexOf("range=");
        if (range_position < 0)
            continue;

        const QByteArray range = options.mid(range_position + 6);
        const qsizetype dash = range.indexOf('-');
        if (dash < 0)
            continue;

        const QByteArray end = range.mid(dash + 1);

        // The end is '*' once the last slice has been read.
        if (end == "*")
            continue;

        bool ok = false;
        const int last = end.toInt(&ok);
        if (!ok)
            continue;

        if (next_start)
            *next_start = last + 1;
        return true;
    }

    return false;
}

//--------------------------------------------------------------------------------------------------
QByteArray ldapNameFromDn(const QByteArray& dn)
{
    QByteArray value;
    bool in_value = false;

    for (qsizetype i = 0; i < dn.size(); ++i)
    {
        const char character = dn.at(i);

        if (!in_value)
        {
            // No '=' in the first RDN: nothing that names anything.
            if (character == ',')
                return QByteArray();

            if (character == '=')
                in_value = true;

            continue;
        }

        if (character == '\\' && i + 1 < dn.size())
        {
            const int high = (i + 2 < dn.size()) ? hexDigit(dn.at(i + 1)) : -1;
            const int low = (i + 2 < dn.size()) ? hexDigit(dn.at(i + 2)) : -1;

            if (high >= 0 && low >= 0)
            {
                value.append(static_cast<char>((high << 4) | low));
                i += 2;
            }
            else
            {
                value.append(dn.at(i + 1));
                ++i;
            }

            continue;
        }

        // A comma separates the RDNs and a plus joins the parts of a multi-valued one; either way the
        // first value is complete.
        if (character == ',' || character == '+')
            break;

        value.append(character);
    }

    return value.trimmed();
}
