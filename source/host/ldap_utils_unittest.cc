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

#include "host/ldap_utils.h"

#include <gtest/gtest.h>

//--------------------------------------------------------------------------------------------------
// The three modes of the settings have to reach the client as the three modes it speaks: a wrong
// answer here would make the resolver speak plaintext where TLS was asked for, or the other way
// around.
TEST(LdapUtilsTest, SecurityModeMapsOneToOne)
{
    EXPECT_EQ(toConnectionSecurity(Database::LdapSecurity::PLAIN),
              LdapConnection::Security::Plain);
    EXPECT_EQ(toConnectionSecurity(Database::LdapSecurity::LDAPS),
              LdapConnection::Security::Ldaps);
    EXPECT_EQ(toConnectionSecurity(Database::LdapSecurity::STARTTLS),
              LdapConnection::Security::StartTls);
}
