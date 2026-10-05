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

#include <gtest/gtest.h>

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>

#include <functional>
#include <optional>

namespace {

//--------------------------------------------------------------------------------------------------
bool waitFor(const std::function<bool()>& predicate, int timeout_ms = 3000)
{
    QElapsedTimer timer;
    timer.start();

    while (!predicate() && timer.elapsed() < timeout_ms)
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);

    return predicate();
}

//--------------------------------------------------------------------------------------------------
LdapCredentialCache::Entry entry()
{
    LdapCredentialCache::Entry result;
    result.resolved = true;
    result.user_name = QStringLiteral("jdoe");
    result.sessions = 1 | 4;
    return result;
}

} // namespace

//--------------------------------------------------------------------------------------------------
// An entry answers only for the exact login, password and configuration that produced it, so neither
// a different password nor changed settings can hit it.
TEST(LdapCredentialCacheTest, MatchesCredentialsAndConfiguration)
{
    LdapCredentialCache& cache = LdapCredentialCache::instance();
    cache.clear();

    const QByteArray hash = cache.credentialHash(QByteArrayLiteral("secret"));
    const QByteArray other_hash = cache.credentialHash(QByteArrayLiteral("other"));
    const QByteArray config_a = QByteArrayLiteral("config-a");
    const QByteArray config_b = QByteArrayLiteral("config-b");

    cache.store(QStringLiteral("jdoe"), hash, config_a, entry(), Seconds(60));

    // The login is matched whatever the case of it is.
    const std::optional<LdapCredentialCache::Entry> hit =
        cache.find(QStringLiteral("JDOE"), hash, config_a);
    ASSERT_TRUE(hit.has_value());
    EXPECT_TRUE(hit->resolved);
    EXPECT_EQ(hit->user_name, QStringLiteral("jdoe"));
    EXPECT_EQ(hit->sessions, (1u | 4u));

    // A different password hash, or a different configuration hash, is a miss.
    EXPECT_FALSE(cache.find(QStringLiteral("jdoe"), other_hash, config_a).has_value());
    EXPECT_FALSE(cache.find(QStringLiteral("jdoe"), hash, config_b).has_value());

    // So is another login.
    EXPECT_FALSE(cache.find(QStringLiteral("other"), hash, config_a).has_value());
}

//--------------------------------------------------------------------------------------------------
// An entry stops answering once its lifetime has passed.
TEST(LdapCredentialCacheTest, EntryExpiresAfterTtl)
{
    LdapCredentialCache& cache = LdapCredentialCache::instance();
    cache.clear();

    const QByteArray hash = cache.credentialHash(QByteArrayLiteral("secret"));
    const QByteArray config_hash = QByteArrayLiteral("config");

    // The shortest lifetime the interface accepts.
    cache.store(QStringLiteral("jdoe"), hash, config_hash, entry(), Seconds(1));
    EXPECT_TRUE(cache.find(QStringLiteral("jdoe"), hash, config_hash).has_value());

    // The entry is gone once the lifetime has elapsed.
    ASSERT_TRUE(waitFor([&]()
    {
        return !cache.find(QStringLiteral("jdoe"), hash, config_hash).has_value();
    })) << "the entry did not expire";
}

//--------------------------------------------------------------------------------------------------
// The cache is bounded: it never holds more than the documented bound, and dropping entries drops the
// oldest, so the newest one survives.
TEST(LdapCredentialCacheTest, StaysWithinBoundAndKeepsNewest)
{
    LdapCredentialCache& cache = LdapCredentialCache::instance();
    cache.clear();

    const QByteArray hash = cache.credentialHash(QByteArrayLiteral("secret"));
    const QByteArray config_hash = QByteArrayLiteral("config");

    // More entries than the bound; the cache must not grow past it.
    for (int i = 0; i < 400; ++i)
        cache.store(QStringLiteral("user%1").arg(i), hash, config_hash, entry(), Seconds(60));

    EXPECT_EQ(cache.count(), 256);

    // The oldest entry has been dropped to make room; the newest one is still there.
    EXPECT_FALSE(cache.find(QStringLiteral("user0"), hash, config_hash).has_value());
    EXPECT_TRUE(cache.find(QStringLiteral("user399"), hash, config_hash).has_value());
}
