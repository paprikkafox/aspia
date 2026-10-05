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

#ifndef HOST_LDAP_CREDENTIAL_RESOLVER_H
#define HOST_LDAP_CREDENTIAL_RESOLVER_H

#include <memory>

#include <QByteArray>
#include <QString>

#include "base/crypto/secure_string.h"
#include "base/peer/credential_resolver.h"
#include "base/time_types.h"

class Database;
class LdapUserResolver;
class Thread;
class UserList;

//--------------------------------------------------------------------------------------------------
// Host-side CredentialResolver: it tries LDAP when it is enabled and falls back to the local account
// (the SRP verifier is recomputed from the supplied password, so no new cryptography is introduced).
class HostLdapCredentialResolver final : public CredentialResolver
{
    Q_OBJECT

public:
    // |database| and |user_list| belong to the thread the resolver is used in and outlive it.
    explicit HostLdapCredentialResolver(Database& database, const UserList& user_list,
                                        QObject* parent = nullptr);
    ~HostLdapCredentialResolver() final;

    void resolve(const QString& login, const SecureString& password) final;
    void cancel() final;

private:
    void onLdapResolved(const QString& user_name, quint32 sessions);
    void onLdapDenied();
    void onLdapFallback();

    void resolveLocal();
    void storeCache(bool resolved, const QString& user_name, quint32 sessions);

    // Emits sig_denied, but not before at least kMinDenyDelay has passed since resolve() started, so
    // the time a refusal takes does not tell an attacker whether the login exists.
    void emitDeniedDelayed();

    // Starts the thread the directory transport lives on; done on first use.
    void ensureLdapThread();

    Database& database_;
    const UserList& user_list_;

    // The directory is spoken to over a Qt socket, and a Qt socket is only told that it has become
    // ready by the standard Qt event dispatcher. The server threads run on the asio dispatcher
    // instead, where those notifications never arrive, so the resolver and its socket live on a
    // thread of its own that uses the standard dispatcher. The thread owns the resolver and deletes
    // it when it finishes.
    std::unique_ptr<Thread> ldap_thread_;
    LdapUserResolver* ldap_resolver_ = nullptr;

    QString login_;
    SecureString password_;
    QByteArray credential_hash_;
    QByteArray config_hash_;
    TimePoint start_time_;
    int cache_ttl_ = 0;
    bool allow_local_fallback_ = true;

    Q_DISABLE_COPY_MOVE(HostLdapCredentialResolver)
};

#endif // HOST_LDAP_CREDENTIAL_RESOLVER_H
