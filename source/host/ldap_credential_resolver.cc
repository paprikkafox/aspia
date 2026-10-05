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

#include "host/ldap_credential_resolver.h"

#include <optional>

#include <QTimer>

#include "base/crypto/big_num.h"
#include "base/crypto/generic_hash.h"
#include "base/crypto/srp_math.h"
#include "base/peer/user_list.h"
#include "base/threading/thread.h"
#include "base/time_types.h"
#include "host/database.h"
#include "host/ldap_credential_cache.h"
#include "host/ldap_user_resolver.h"

namespace {

// A refusal is never reported sooner than this after the credentials arrived, so the time a failure
// takes says nothing about whether the login exists in the directory.
constexpr MilliSeconds kMinDenyDelay{ 1000 };

//--------------------------------------------------------------------------------------------------
// A fingerprint of everything the resolution depends on. It is stored with a cache entry, so a change
// to the server, the bind account, a filter or a mapping turns the entry into a miss instead of
// granting rights that the new configuration no longer gives.
QByteArray configFingerprint(const Database::LdapConfig& config,
                             const QVector<Database::LdapMapping>& groups,
                             const QVector<Database::LdapMapping>& users)
{
    GenericHash hash(GenericHash::SHA256);

    const auto add_text = [&hash](const QString& text)
    {
        hash.addData(text.toUtf8());
    };

    const auto add_number = [&hash](quint32 number)
    {
        hash.addData(QByteArray::number(number));
    };

    add_text(config.server);
    add_number(config.port);
    add_number(static_cast<quint32>(config.security));
    add_number(config.enabled ? 1 : 0);
    add_text(config.bind_dn);
    add_text(config.bind_password);
    add_text(config.base_dn);
    add_text(config.user_filter);
    add_text(config.user_name_attribute);
    add_number(config.group_nested ? 1 : 0);
    add_text(config.group_base_dn);
    add_text(config.group_filter);
    add_text(config.group_attribute);
    add_number(config.default_sessions);
    add_number(config.deny_if_unmapped ? 1 : 0);
    add_number(config.allow_local_fallback ? 1 : 0);

    for (const Database::LdapMapping& mapping : groups)
    {
        add_text(mapping.name);
        add_number(mapping.sessions);
    }

    for (const Database::LdapMapping& mapping : users)
    {
        add_text(mapping.name);
        add_number(mapping.sessions);
    }

    return hash.result();
}

} // namespace

//--------------------------------------------------------------------------------------------------
HostLdapCredentialResolver::HostLdapCredentialResolver(Database& database, const UserList& user_list,
                                                       QObject* parent)
    : CredentialResolver(parent),
      database_(database),
      user_list_(user_list)
{
    // Nothing
}

//--------------------------------------------------------------------------------------------------
HostLdapCredentialResolver::~HostLdapCredentialResolver()
{
    // The resolver is deleted on the thread it lives on once that thread has finished, so its socket
    // and timer are torn down there. Stopping the thread is all that remains.
    if (ldap_thread_)
        ldap_thread_->stop();

    ldap_resolver_ = nullptr;
}

//--------------------------------------------------------------------------------------------------
void HostLdapCredentialResolver::ensureLdapThread()
{
    if (ldap_thread_)
        return;

    ldap_thread_ = std::make_unique<Thread>(Thread::QtDispatcher);

    // An object can only be moved to another thread while it has no parent.
    ldap_resolver_ = new LdapUserResolver();
    ldap_resolver_->moveToThread(ldap_thread_.get());

    connect(ldap_resolver_, &LdapUserResolver::sig_resolved, this,
            &HostLdapCredentialResolver::onLdapResolved);
    connect(ldap_resolver_, &LdapUserResolver::sig_denied, this,
            &HostLdapCredentialResolver::onLdapDenied);
    connect(ldap_resolver_, &LdapUserResolver::sig_fallbackToLocal, this,
            &HostLdapCredentialResolver::onLdapFallback);

    // The thread owns the resolver and deletes it on the thread once it has finished.
    connect(ldap_thread_.get(), &QThread::finished, ldap_resolver_, &QObject::deleteLater);

    ldap_thread_->start();
}

//--------------------------------------------------------------------------------------------------
void HostLdapCredentialResolver::resolve(const QString& login, const SecureString& password)
{
    login_ = login;
    password_ = password;
    start_time_ = Clock::now();

    const Database::LdapConfig config = database_.ldapConfig();
    cache_ttl_ = config.cache_ttl;
    allow_local_fallback_ = config.allow_local_fallback;

    const QVector<Database::LdapMapping> groups = database_.ldapGroups();
    const QVector<Database::LdapMapping> users = database_.ldapUsers();

    if (cache_ttl_ > 0)
    {
        credential_hash_ =
            LdapCredentialCache::instance().credentialHash(password_.toUtf8().toByteArray());
        config_hash_ = configFingerprint(config, groups, users);

        const std::optional<LdapCredentialCache::Entry> hit =
            LdapCredentialCache::instance().find(login_, credential_hash_, config_hash_);
        if (hit.has_value())
        {
            if (hit->resolved)
                emit sig_resolved(hit->user_name, hit->sessions);
            else
                emitDeniedDelayed();
            return;
        }
    }
    else
    {
        credential_hash_.clear();
        config_hash_.clear();
    }

    if (!config.enabled)
    {
        // LDAP is off: only local accounts can authenticate.
        resolveLocal();
        return;
    }

    // A directory that cannot even be asked, because the server or the settings a search needs are
    // missing, is decided locally without starting the transport thread. LDAP-only mode denies
    // instead.
    if (config.server.isEmpty() || config.base_dn.isEmpty() || config.user_filter.isEmpty() ||
        config.user_name_attribute.isEmpty())
    {
        if (allow_local_fallback_)
            resolveLocal();
        else
            emitDeniedDelayed();
        return;
    }

    ensureLdapThread();

    // The whole exchange runs on the transport thread; the settings travel with the call.
    LdapUserResolver* resolver = ldap_resolver_;
    QMetaObject::invokeMethod(resolver, [resolver, config, groups, users, login, password]()
    {
        resolver->setConfig(config);
        resolver->setMappings(groups, users);
        resolver->resolve(login, password);
    }, Qt::QueuedConnection);
}

//--------------------------------------------------------------------------------------------------
void HostLdapCredentialResolver::cancel()
{
    LdapUserResolver* resolver = ldap_resolver_;
    if (!resolver)
        return;

    // The resolver lives on the transport thread, so even the cancel is handed over to it.
    QMetaObject::invokeMethod(resolver, [resolver]() { resolver->cancel(); }, Qt::QueuedConnection);
}

//--------------------------------------------------------------------------------------------------
void HostLdapCredentialResolver::onLdapResolved(const QString& user_name, quint32 sessions)
{
    storeCache(true, user_name, sessions);
    emit sig_resolved(user_name, sessions);
}

//--------------------------------------------------------------------------------------------------
void HostLdapCredentialResolver::onLdapDenied()
{
    // LDAP is authoritative: the user exists there, so a wrong password is not retried locally.
    storeCache(false, QString(), 0);
    emitDeniedDelayed();
}

//--------------------------------------------------------------------------------------------------
void HostLdapCredentialResolver::onLdapFallback()
{
    // In "LDAP only" mode a directory that cannot decide denies instead of falling back.
    if (!allow_local_fallback_)
    {
        emitDeniedDelayed();
        return;
    }

    resolveLocal();
}

//--------------------------------------------------------------------------------------------------
void HostLdapCredentialResolver::resolveLocal()
{
    // The list is the same source the SRP path uses, so a one-time user, which lives in the list and
    // not in the database, is found here too.
    const User user = user_list_.find(login_);

    bool resolved = false;
    quint32 sessions = 0;

    if (user.isValid() && (user.flags & User::ENABLED))
    {
        const std::optional<SrpMath::NgPair> ng_pair = SrpMath::pairByGroup(user.group);
        if (ng_pair.has_value())
        {
            // Recompute the verifier from the supplied password and compare it with the stored one.
            // The same SrpMath used by the SRP path, so the recomputation mirrors what was stored.
            const BigNum s = BigNum::fromByteArray(user.salt);
            const BigNum N = BigNum::fromStdString(ng_pair->first);
            const BigNum g = BigNum::fromStdString(ng_pair->second);
            const BigNum v = SrpMath::calc_v(login_, password_, s, N, g);

            if (v.isValid() && v.toByteArray() == user.verifier)
            {
                resolved = true;
                sessions = user.sessions;
            }
        }
    }

    if (resolved)
    {
        storeCache(true, user.name, sessions);
        emit sig_resolved(user.name, sessions);
    }
    else
    {
        storeCache(false, QString(), 0);
        emitDeniedDelayed();
    }
}

//--------------------------------------------------------------------------------------------------
void HostLdapCredentialResolver::storeCache(bool resolved, const QString& user_name, quint32 sessions)
{
    if (cache_ttl_ <= 0)
        return;

    LdapCredentialCache::Entry entry;
    entry.resolved = resolved;
    entry.user_name = user_name;
    entry.sessions = sessions;

    LdapCredentialCache::instance().store(login_, credential_hash_, config_hash_, entry,
                                          Seconds(cache_ttl_));
}

//--------------------------------------------------------------------------------------------------
void HostLdapCredentialResolver::emitDeniedDelayed()
{
    const TimePoint earliest = start_time_ + kMinDenyDelay;
    const TimePoint now = Clock::now();

    if (now >= earliest)
    {
        emit sig_denied();
        return;
    }

    // The timer is tied to this object, so it is dropped if the resolver goes away first.
    QTimer::singleShot(DurationCast<MilliSeconds>(earliest - now), this,
                       [this]() { emit sig_denied(); });
}
