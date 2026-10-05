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

#include "host/ldap_credential_cache.h"

#include <QMutexLocker>

#include "base/crypto/generic_hash.h"
#include "base/crypto/random.h"

namespace {

constexpr int kProcessKeySize = 32;

} // namespace

//--------------------------------------------------------------------------------------------------
// static
LdapCredentialCache& LdapCredentialCache::instance()
{
    static LdapCredentialCache cache;
    return cache;
}

//--------------------------------------------------------------------------------------------------
LdapCredentialCache::LdapCredentialCache()
    : process_key_(Random::byteArray(kProcessKeySize))
{
    // Nothing
}

//--------------------------------------------------------------------------------------------------
QByteArray LdapCredentialCache::credentialHash(const QByteArray& password) const
{
    GenericHash hash(GenericHash::SHA256);
    hash.addData(process_key_);
    hash.addData(password);
    return hash.result();
}

//--------------------------------------------------------------------------------------------------
std::optional<LdapCredentialCache::Entry> LdapCredentialCache::find(
    const QString& login, const QByteArray& credential_hash, const QByteArray& config_hash)
{
    QMutexLocker locker(&mutex_);

    const auto it = entries_.constFind(login.toCaseFolded());
    if (it == entries_.constEnd())
        return std::nullopt;

    // A different password or a changed configuration must not be served from the cache.
    if (it->credential_hash != credential_hash || it->config_hash != config_hash)
        return std::nullopt;

    if (Clock::now() >= it->expires)
    {
        entries_.erase(it);
        return std::nullopt;
    }

    return it->entry;
}

//--------------------------------------------------------------------------------------------------
void LdapCredentialCache::store(const QString& login, const QByteArray& credential_hash,
                                const QByteArray& config_hash, const Entry& entry, Seconds ttl)
{
    if (ttl <= Seconds(0))
        return;

    QMutexLocker locker(&mutex_);

    evict();

    Stored stored;
    stored.credential_hash = credential_hash;
    stored.config_hash = config_hash;
    stored.entry = entry;
    stored.stored_at = Clock::now();
    stored.expires = stored.stored_at + ttl;

    entries_.insert(login.toCaseFolded(), stored);
}

//--------------------------------------------------------------------------------------------------
void LdapCredentialCache::clear()
{
    QMutexLocker locker(&mutex_);
    entries_.clear();
}

//--------------------------------------------------------------------------------------------------
int LdapCredentialCache::count() const
{
    QMutexLocker locker(&mutex_);
    return entries_.size();
}

//--------------------------------------------------------------------------------------------------
void LdapCredentialCache::evict()
{
    const TimePoint now = Clock::now();

    for (auto it = entries_.begin(); it != entries_.end(); )
    {
        if (now >= it->expires)
            it = entries_.erase(it);
        else
            ++it;
    }

    while (entries_.size() >= kMaxEntries)
    {
        auto oldest = entries_.begin();
        for (auto it = entries_.begin(); it != entries_.end(); ++it)
        {
            if (it->stored_at < oldest->stored_at)
                oldest = it;
        }

        entries_.erase(oldest);
    }
}
