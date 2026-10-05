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

#include <functional>

#include <QCoreApplication>
#include <QTemporaryDir>

#include <gtest/gtest.h>

#include "base/crypto/secure_string.h"
#include "base/time_types.h"
#include "host/database.h"
#include "host/ldap_credential_cache.h"

namespace {

// Runs the event loop until |predicate| turns true or |timeout| elapses. The credential resolver
// reports a refusal only after a minimum delay (anti-enumeration), so a test must let the timer fire.
bool waitFor(const std::function<bool()>& predicate, MilliSeconds timeout = MilliSeconds(10000))
{
    const TimePoint deadline = Clock::now() + timeout;

    while (!predicate() && Clock::now() < deadline)
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);

    return predicate();
}

} // namespace

// What the authenticator of the host sees when a peer names itself: the stored users and the
// one-time user that only lives while the router hands out an id for it.
class HostUserListTest : public testing::Test
{
protected:
    void SetUp() override
    {
        ASSERT_TRUE(temp_dir_.isValid());

        db_ = Database::openForTesting(temp_dir_.path() + "/host.db3");
        ASSERT_TRUE(db_);

        // The resolution cache is shared by the whole process, so a test starts from a clean one.
        LdapCredentialCache::instance().clear();

        list_ = std::make_unique<HostUserList>(*db_);
    }

    static User user(const QString& name, const QString& password)
    {
        return User::create(name, SecureString(password));
    }

    // LDAP is on but the server is empty: the resolver cannot reach a directory and decides locally,
    // which keeps a test deterministic and offline.
    // The password method is offered only when LDAP is on.
    void enableOfflineLdap(bool allow_local_fallback = true)
    {
        Database::LdapConfig config;
        config.enabled = true;
        config.server = QString();
        config.base_dn = QStringLiteral("dc=x");
        config.user_filter = QStringLiteral("(uid=%1)");
        config.user_name_attribute = QStringLiteral("uid");
        config.allow_local_fallback = allow_local_fallback;
        ASSERT_TRUE(db_->setLdapConfig(config));
    }

    QTemporaryDir temp_dir_;
    std::unique_ptr<Database> db_;
    std::unique_ptr<HostUserList> list_;
};

//--------------------------------------------------------------------------------------------------
// A stored user is found with the material the authenticator needs.
TEST_F(HostUserListTest, StoredUserIsFound)
{
    ASSERT_TRUE(db_->addUser(user("john", "password")));

    const User found = list_->find("john");
    ASSERT_TRUE(found.isValid());
    EXPECT_EQ(found.name, QString("john"));
    EXPECT_FALSE(found.salt.isEmpty());
    EXPECT_FALSE(found.verifier.isEmpty());
}

//--------------------------------------------------------------------------------------------------
// A name nobody has is not somebody to authenticate.
TEST_F(HostUserListTest, UnknownNameIsNotFound)
{
    EXPECT_FALSE(list_->find("john").isValid());
}

//--------------------------------------------------------------------------------------------------
// The one-time user is not in the database and is still found, which is what makes the one-time
// password work.
TEST_F(HostUserListTest, OneTimeUserIsFound)
{
    list_->setOneTimeUser(user("#123456", "one-time"));

    const User found = list_->find("#123456");
    ASSERT_TRUE(found.isValid());
    EXPECT_EQ(found.name, QString("#123456"));
    EXPECT_FALSE(db_->findUser(QString("#123456")).isValid());
}

//--------------------------------------------------------------------------------------------------
// The user types the name and the case of it is not part of what they were told.
TEST_F(HostUserListTest, OneTimeUserIsFoundWhateverTheCase)
{
    list_->setOneTimeUser(user("#abc", "one-time"));

    EXPECT_TRUE(list_->find("#ABC").isValid());
    EXPECT_TRUE(list_->find("#Abc").isValid());
}

//--------------------------------------------------------------------------------------------------
// While there is no id from the router there is no one-time user either, so the name it used to
// answer to authenticates nobody.
TEST_F(HostUserListTest, ClearedOneTimeUserIsNotFound)
{
    list_->setOneTimeUser(user("#123456", "one-time"));
    ASSERT_TRUE(list_->find("#123456").isValid());

    list_->setOneTimeUser(User());

    EXPECT_FALSE(list_->find("#123456").isValid());
}

//--------------------------------------------------------------------------------------------------
// A one-time user replaces the previous one instead of adding to it: only the credentials the user
// is being shown right now open a session.
TEST_F(HostUserListTest, OneTimeUserReplacesThePreviousOne)
{
    list_->setOneTimeUser(user("#111", "one-time"));
    list_->setOneTimeUser(user("#222", "one-time"));

    EXPECT_FALSE(list_->find("#111").isValid());
    EXPECT_TRUE(list_->find("#222").isValid());
}

//--------------------------------------------------------------------------------------------------
// A stored user of that name answers first. The administrator of the host decides who its users
// are, and a one-time name must not take a stored name over.
TEST_F(HostUserListTest, StoredUserWinsOverTheOneTimeName)
{
    const User stored = user("#123456", "stored");
    ASSERT_TRUE(db_->addUser(stored));

    list_->setOneTimeUser(user("#123456", "one-time"));

    const User found = list_->find("#123456");
    ASSERT_TRUE(found.isValid());
    EXPECT_EQ(found.verifier, stored.verifier);
}

//--------------------------------------------------------------------------------------------------
// The seed key of the authenticator is kept in the database, so it is the same one after a restart.
TEST_F(HostUserListTest, SeedKeyGoesThroughTheDatabase)
{
    const QByteArray seed("\x00\x11\x22 seed", 7);

    list_->setSeedKey(seed);

    EXPECT_EQ(db_->seedKey(), seed);
    EXPECT_EQ(list_->seedKey(), seed);
}

//--------------------------------------------------------------------------------------------------
// With LDAP off the credential resolver validates against the local account: it recomputes the SRP
// verifier from the supplied password and compares it with the stored one.
TEST_F(HostUserListTest, CredentialResolverValidatesLocalPassword)
{
    User stored = user("john", "password");
    stored.sessions = 1 | 4;
    stored.flags = User::ENABLED;
    ASSERT_TRUE(db_->addUser(stored));

    // The password method exists only while LDAP is on; the resolver then falls back to the local
    // account because the directory cannot be reached.
    enableOfflineLdap();

    std::unique_ptr<CredentialResolver> resolver = list_->createCredentialResolver();
    ASSERT_TRUE(resolver);

    QString name;
    quint32 sessions = 0;
    bool denied = false;

    QObject::connect(resolver.get(), &CredentialResolver::sig_resolved, resolver.get(),
                     [&](const QString& resolved_name, quint32 resolved_sessions)
    {
        name = resolved_name;
        sessions = resolved_sessions;
    });
    QObject::connect(resolver.get(), &CredentialResolver::sig_denied, resolver.get(),
                     [&]() { denied = true; });

    // LDAP is disabled by default, so the resolution is local and synchronous.
    resolver->resolve(QStringLiteral("john"), SecureString(QStringLiteral("password")));
    EXPECT_FALSE(denied);
    EXPECT_EQ(name, QStringLiteral("john"));
    EXPECT_EQ(sessions, (1u | 4u));

    name.clear();
    sessions = 0;
    denied = false;

    resolver->resolve(QStringLiteral("john"), SecureString(QStringLiteral("wrong")));
    EXPECT_TRUE(waitFor([&]() { return denied; }));
    EXPECT_TRUE(name.isEmpty());
    EXPECT_EQ(sessions, 0u);

    // An unknown login is denied too.
    denied = false;
    resolver->resolve(QStringLiteral("nobody"), SecureString(QStringLiteral("password")));
    EXPECT_TRUE(waitFor([&]() { return denied; }));
}

//--------------------------------------------------------------------------------------------------
// A resolution is cached for the configured TTL. The cache is keyed by the login and a hash of the
// password, so only the exact credentials that produced an entry can hit it.
TEST_F(HostUserListTest, CredentialResolverCachesResults)
{
    User stored = user("john", "password");
    stored.sessions = 1;
    stored.flags = User::ENABLED;
    ASSERT_TRUE(db_->addUser(stored));

    enableOfflineLdap();

    std::unique_ptr<CredentialResolver> resolver = list_->createCredentialResolver();
    ASSERT_TRUE(resolver);

    int resolved_count = 0;
    int denied_count = 0;

    QObject::connect(resolver.get(), &CredentialResolver::sig_resolved, resolver.get(),
                     [&](const QString&, quint32) { ++resolved_count; });
    QObject::connect(resolver.get(), &CredentialResolver::sig_denied, resolver.get(),
                     [&]() { ++denied_count; });

    resolver->resolve(QStringLiteral("john"), SecureString(QStringLiteral("password")));
    EXPECT_EQ(resolved_count, 1);

    // Remove the account; the cached positive result still stands within its TTL.
    const User found = db_->findUser(QStringLiteral("john"));
    ASSERT_TRUE(found.isValid());
    ASSERT_TRUE(db_->removeUser(found.entry_id));

    resolver->resolve(QStringLiteral("john"), SecureString(QStringLiteral("password")));
    EXPECT_EQ(resolved_count, 2);
    EXPECT_EQ(denied_count, 0);

    // A different password is a different cache key, so it goes to the (now empty) local store.
    resolver->resolve(QStringLiteral("john"), SecureString(QStringLiteral("other")));
    EXPECT_TRUE(waitFor([&]() { return denied_count == 1; }));
}

//--------------------------------------------------------------------------------------------------
// The "LDAP only" policy denies when the directory cannot decide, while the default policy falls
// back to the local account.
TEST_F(HostUserListTest, LocalFallbackPolicy)
{
    User stored = user("john", "password");
    stored.sessions = 1 | 4;
    stored.flags = User::ENABLED;
    ASSERT_TRUE(db_->addUser(stored));

    // LDAP is enabled but the server is empty: the resolver cannot decide without touching the
    // network, which keeps this test deterministic.
    Database::LdapConfig config;
    config.enabled = true;
    config.server = QString();
    config.base_dn = QStringLiteral("dc=x");
    config.user_filter = QStringLiteral("(uid=%1)");
    config.user_name_attribute = QStringLiteral("uid");

    // LDAP preferred: falls back to the local account.
    config.allow_local_fallback = true;
    ASSERT_TRUE(db_->setLdapConfig(config));

    {
        std::unique_ptr<CredentialResolver> resolver = list_->createCredentialResolver();
        ASSERT_TRUE(resolver);

        bool resolved = false;
        quint32 sessions = 0;
        QObject::connect(resolver.get(), &CredentialResolver::sig_resolved, resolver.get(),
                         [&](const QString&, quint32 value) { resolved = true; sessions = value; });
        QObject::connect(resolver.get(), &CredentialResolver::sig_denied, resolver.get(),
                         [&]() { ADD_FAILURE() << "unexpected denial"; });

        resolver->resolve(QStringLiteral("john"), SecureString(QStringLiteral("password")));
        EXPECT_TRUE(resolved);
        EXPECT_EQ(sessions, (1u | 4u));
    }

    // LDAP only: the same credentials are denied.
    config.allow_local_fallback = false;
    ASSERT_TRUE(db_->setLdapConfig(config));

    {
        std::unique_ptr<CredentialResolver> resolver = list_->createCredentialResolver();
        ASSERT_TRUE(resolver);

        bool denied = false;
        QObject::connect(resolver.get(), &CredentialResolver::sig_resolved, resolver.get(),
                         [&](const QString&, quint32) { ADD_FAILURE() << "unexpected resolution"; });
        QObject::connect(resolver.get(), &CredentialResolver::sig_denied, resolver.get(),
                         [&]() { denied = true; });

        resolver->resolve(QStringLiteral("john"), SecureString(QStringLiteral("password")));
        EXPECT_TRUE(waitFor([&]() { return denied; }));
    }
}

//--------------------------------------------------------------------------------------------------
// A host with LDAP off keeps SRP: it does not offer the password method at all, so a local account is
// never downgraded to sending its password.
TEST_F(HostUserListTest, NoPasswordMethodWithoutLdap)
{
    User stored = user("john", "password");
    stored.flags = User::ENABLED;
    ASSERT_TRUE(db_->addUser(stored));

    // LDAP is disabled by default.
    EXPECT_FALSE(list_->createCredentialResolver());

    enableOfflineLdap();
    EXPECT_TRUE(list_->createCredentialResolver());
}

//--------------------------------------------------------------------------------------------------
// The one-time user lives in the list, not in the database, and the password path must find it the
// same way the SRP path does: that is what makes a one-time password work over a brokered connection.
TEST_F(HostUserListTest, CredentialResolverAuthenticatesTheOneTimeUser)
{
    // The list is populated the way RouterManager does it, flags included.
    User one_time_user = user("#123456", "one-time");
    one_time_user.sessions = 1 | 4;
    one_time_user.flags = User::ENABLED;
    list_->setOneTimeUser(one_time_user);

    // LDAP on but unreachable: the resolution falls back to the list, which holds the one-time user.
    enableOfflineLdap();

    std::unique_ptr<CredentialResolver> resolver = list_->createCredentialResolver();
    ASSERT_TRUE(resolver);

    bool resolved = false;
    quint32 sessions = 0;
    QObject::connect(resolver.get(), &CredentialResolver::sig_resolved, resolver.get(),
                     [&](const QString&, quint32 value) { resolved = true; sessions = value; });
    QObject::connect(resolver.get(), &CredentialResolver::sig_denied, resolver.get(),
                     [&]() { ADD_FAILURE() << "unexpected denial"; });

    resolver->resolve(QStringLiteral("#123456"), SecureString(QStringLiteral("one-time")));
    EXPECT_TRUE(resolved);
    EXPECT_EQ(sessions, (1u | 4u));
}

//--------------------------------------------------------------------------------------------------
// The resolution cache only answers for the exact credentials and the exact configuration that
// produced the entry, so neither a different password nor changed settings can hit it.
TEST_F(HostUserListTest, CredentialCacheMatchesCredentialsAndConfiguration)
{
    LdapCredentialCache& cache = LdapCredentialCache::instance();
    cache.clear();

    const QByteArray hash = cache.credentialHash(QByteArrayLiteral("password"));
    const QByteArray other_hash = cache.credentialHash(QByteArrayLiteral("other"));
    const QByteArray config_a = QByteArrayLiteral("config-a");
    const QByteArray config_b = QByteArrayLiteral("config-b");

    LdapCredentialCache::Entry entry;
    entry.resolved = true;
    entry.user_name = QStringLiteral("john");
    entry.sessions = 1 | 4;

    cache.store(QStringLiteral("John"), hash, config_a, entry, Seconds(60));

    // The login is matched whatever the case of it is.
    const std::optional<LdapCredentialCache::Entry> hit =
        cache.find(QStringLiteral("john"), hash, config_a);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->sessions, (1u | 4u));
    EXPECT_EQ(hit->user_name, QStringLiteral("john"));

    // A different password, or a changed configuration, is a miss.
    EXPECT_FALSE(cache.find(QStringLiteral("john"), other_hash, config_a).has_value());
    EXPECT_FALSE(cache.find(QStringLiteral("john"), hash, config_b).has_value());
    EXPECT_FALSE(cache.find(QStringLiteral("mary"), hash, config_a).has_value());

    // A zero TTL stores nothing.
    cache.store(QStringLiteral("mary"), hash, config_a, entry, Seconds(0));
    EXPECT_FALSE(cache.find(QStringLiteral("mary"), hash, config_a).has_value());

    // The stored value is a keyed hash of the password, never the password itself.
    EXPECT_NE(hash, QByteArrayLiteral("password"));

    // The cache is bounded, so an attacker cannot grow it without limit.
    for (int i = 0; i < 400; ++i)
        cache.store(QStringLiteral("user%1").arg(i), hash, config_a, entry, Seconds(60));
    EXPECT_LE(cache.count(), 256);
}
