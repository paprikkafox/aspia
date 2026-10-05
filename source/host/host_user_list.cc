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

#include "host/host_user_list.h"

#include "host/database.h"
#include "host/ldap_credential_resolver.h"

//--------------------------------------------------------------------------------------------------
HostUserList::HostUserList(Database& database)
    : database_(database)
{
    // Nothing
}

//--------------------------------------------------------------------------------------------------
User HostUserList::find(const QString& username) const
{
    User user(database_.findUser(username));
    if (user.isValid())
        return user;

    if (one_time_user_.isValid() && one_time_user_.name.compare(username, Qt::CaseInsensitive) == 0)
        return one_time_user_;

    return User();
}

//--------------------------------------------------------------------------------------------------
QByteArray HostUserList::seedKey() const
{
    return database_.seedKey();
}

//--------------------------------------------------------------------------------------------------
void HostUserList::setSeedKey(const QByteArray& seed_key)
{
    database_.setSeedKey(seed_key);
}

//--------------------------------------------------------------------------------------------------
void HostUserList::setOneTimeUser(const User& user)
{
    one_time_user_ = user;
}

//--------------------------------------------------------------------------------------------------
std::unique_ptr<CredentialResolver> HostUserList::createCredentialResolver()
{
    // The password method exists for the directory. Without LDAP a local account is checked with SRP,
    // which never lets the password leave the client, so a host with LDAP off must not offer the
    // password method at all - otherwise every connection would downgrade SRP to a plain password.
    if (!database_.ldapConfig().enabled)
        return nullptr;

    // The list is passed so the local fallback sees the same users the SRP path sees, the one-time
    // user among them.
    return std::make_unique<HostLdapCredentialResolver>(database_, *this);
}
