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

#ifndef HOST_LDAP_UTILS_H
#define HOST_LDAP_UTILS_H

#include "base/ldap/ldap_connection.h"
#include "host/database.h"

//--------------------------------------------------------------------------------------------------
// The transport mode of the settings, as the LDAP client sees it.
inline LdapConnection::Security toConnectionSecurity(Database::LdapSecurity security)
{
    switch (security)
    {
        case Database::LdapSecurity::PLAIN:    return LdapConnection::Security::Plain;
        case Database::LdapSecurity::LDAPS:    return LdapConnection::Security::Ldaps;
        case Database::LdapSecurity::STARTTLS: return LdapConnection::Security::StartTls;
    }

    return LdapConnection::Security::StartTls;
}

#endif // HOST_LDAP_UTILS_H
