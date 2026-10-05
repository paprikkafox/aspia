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

#ifndef HOST_LDAP_CREDENTIAL_CACHE_H
#define HOST_LDAP_CREDENTIAL_CACHE_H

#include <QByteArray>
#include <QHash>
#include <QMutex>
#include <QString>

#include <optional>

#include "base/time_types.h"

//--------------------------------------------------------------------------------------------------
// A process-wide cache of LDAP credential resolutions, so that repeated authentications within the
// TTL do not query the directory again. Every connection shares it, so a mutex guards it.
//
// The password itself is never kept. An entry is keyed by a hash of the password and a key that lives
// only in this process, so it matches only the credentials that produced it: a wrong password cannot
// hit a positive entry, and a memory dump does not hand out a directly crackable hash of a password.
// An entry also carries a fingerprint of the LDAP configuration and the mappings that produced it, so
// changing the settings turns the entry into a miss instead of granting stale rights. The cache is
// bounded: expired entries go first, then the oldest while it is still full, so it cannot be grown
// without limit.
class LdapCredentialCache final
{
public:
    struct Entry
    {
        bool resolved = false;
        QString user_name;
        quint32 sessions = 0;
    };

    static LdapCredentialCache& instance();

    // The value an entry is keyed by. It mixes the password with a key that lives only in this
    // process, so the stored value is not usable without the process memory.
    [[nodiscard]] QByteArray credentialHash(const QByteArray& password) const;

    // The entry stored for |login| with these credentials and this configuration, if one is still
    // valid. A different password or a different configuration is a miss.
    [[nodiscard]] std::optional<Entry> find(const QString& login, const QByteArray& credential_hash,
                                            const QByteArray& config_hash);

    void store(const QString& login, const QByteArray& credential_hash,
               const QByteArray& config_hash, const Entry& entry, Seconds ttl);

    void clear();

    // The number of entries held; a test hook for the bound.
    [[nodiscard]] int count() const;

private:
    LdapCredentialCache();
    ~LdapCredentialCache() = default;

    // Beyond this the oldest entries are dropped; a host serves a single user, so a handful of
    // entries is all a real workload needs and the cap only bounds what an attacker can add.
    static constexpr int kMaxEntries = 256;

    struct Stored
    {
        QByteArray credential_hash;
        QByteArray config_hash;
        Entry entry;
        TimePoint stored_at;
        TimePoint expires;
    };

    // Drops expired entries, then the oldest ones until there is room. The mutex must be held.
    void evict();

    const QByteArray process_key_;
    QHash<QString, Stored> entries_;
    mutable QMutex mutex_;

    Q_DISABLE_COPY_MOVE(LdapCredentialCache)
};

#endif // HOST_LDAP_CREDENTIAL_CACHE_H
