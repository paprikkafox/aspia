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

#include "host/settings_util.h"

#include <QFile>
#include <QSettings>
#include <QTemporaryDir>

#include <gtest/gtest.h>

#include "base/peer/user.h"
#include "host/database.h"

// SettingsUtil works on the per-thread connection of Database::instance(), so a test points that
// connection at a file of its own.
class DatabaseTestPeer
{
public:
    static void setFilePath(const QString& file_path) { Database::setFilePathForTesting(file_path); }
};

class SettingsUtilTest : public testing::Test
{
protected:
    void SetUp() override
    {
        ASSERT_TRUE(temp_dir_.isValid());

        // The settings of the machine are kept in the system scope; the file this test writes stays
        // inside the temporary directory, so nothing outside it is touched.
        QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope, temp_dir_.path());

        DatabaseTestPeer::setFilePath(temp_dir_.path() + "/host.db3");
        ASSERT_TRUE(Database::instance().isValid());

        path_ = temp_dir_.path() + "/settings.json";
    }

    void TearDown() override
    {
        // Closes the file before the temporary directory is removed.
        DatabaseTestPeer::setFilePath(QString());
    }

    static Database::LdapConfig ldapConfig()
    {
        Database::LdapConfig config;
        config.enabled = true;
        config.server = QStringLiteral("dc01.example.com");
        config.port = 389;
        config.security = Database::LdapSecurity::STARTTLS;
        config.verify_peer = false;
        config.ca_certificate = QStringLiteral("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----");
        config.bind_dn = QStringLiteral("CN=svc-aspia,OU=Service Accounts,DC=example,DC=com");
        config.bind_password = QStringLiteral("Secret123!");
        config.base_dn = QStringLiteral("DC=example,DC=com");
        config.user_filter = QStringLiteral("(&(objectCategory=person)(sAMAccountName=%1))");
        config.user_name_attribute = QStringLiteral("sAMAccountName");
        config.group_nested = true;
        config.group_base_dn = QStringLiteral("DC=example,DC=com");
        config.group_filter = QStringLiteral("(objectClass=group)");
        config.group_attribute = QStringLiteral("memberOf");
        config.default_sessions = 8;
        config.deny_if_unmapped = false;
        config.allow_local_fallback = false;
        config.cache_ttl = 300;
        return config;
    }

    QTemporaryDir temp_dir_;
    QString path_;
};

//--------------------------------------------------------------------------------------------------
// The LDAP settings and the mappings they feed are part of the host configuration, so a file written
// from one host has to bring them to another.
TEST_F(SettingsUtilTest, LdapSettingsSurviveARoundTrip)
{
    const Database::LdapConfig config = ldapConfig();
    ASSERT_TRUE(Database::instance().setLdapConfig(config));

    Database::LdapMapping group;
    group.name = QStringLiteral("CN=Aspia-Admins,OU=Aspia,DC=example,DC=com");
    group.sessions = 1 | 4 | 8 | 16 | 32;
    group.flags = User::ENABLED;
    ASSERT_TRUE(Database::instance().addLdapGroup(group));

    Database::LdapMapping user;
    user.name = QStringLiteral("petrov");
    user.sessions = 4;
    user.flags = User::ENABLED;
    ASSERT_TRUE(Database::instance().addLdapUser(user));

    ASSERT_TRUE(SettingsUtil::exportToFile(path_, /* silent */ true));

    // The host settings are cleared, so only the file can restore them.
    ASSERT_TRUE(Database::instance().setLdapConfig(Database::LdapConfig()));
    ASSERT_TRUE(Database::instance().replaceLdapGroups({}));
    ASSERT_TRUE(Database::instance().replaceLdapUsers({}));

    ASSERT_TRUE(SettingsUtil::importFromFile(path_, /* silent */ true));

    const Database::LdapConfig loaded = Database::instance().ldapConfig();
    EXPECT_TRUE(loaded.enabled);
    EXPECT_EQ(loaded.server, config.server);
    EXPECT_EQ(loaded.port, config.port);
    EXPECT_EQ(loaded.security, config.security);
    EXPECT_FALSE(loaded.verify_peer);
    EXPECT_EQ(loaded.ca_certificate, config.ca_certificate);
    EXPECT_EQ(loaded.bind_dn, config.bind_dn);
    EXPECT_EQ(loaded.bind_password, config.bind_password);
    EXPECT_EQ(loaded.base_dn, config.base_dn);
    EXPECT_EQ(loaded.user_filter, config.user_filter);
    EXPECT_EQ(loaded.user_name_attribute, config.user_name_attribute);
    EXPECT_TRUE(loaded.group_nested);
    EXPECT_EQ(loaded.group_base_dn, config.group_base_dn);
    EXPECT_EQ(loaded.group_filter, config.group_filter);
    EXPECT_EQ(loaded.group_attribute, config.group_attribute);
    EXPECT_EQ(loaded.default_sessions, config.default_sessions);
    EXPECT_FALSE(loaded.deny_if_unmapped);
    EXPECT_FALSE(loaded.allow_local_fallback);
    EXPECT_EQ(loaded.cache_ttl, config.cache_ttl);

    const QVector<Database::LdapMapping> groups = Database::instance().ldapGroups();
    ASSERT_EQ(groups.size(), 1);
    EXPECT_EQ(groups.first().name, group.name);
    EXPECT_EQ(groups.first().sessions, group.sessions);

    const QVector<Database::LdapMapping> users = Database::instance().ldapUsers();
    ASSERT_EQ(users.size(), 1);
    EXPECT_EQ(users.first().name, user.name);
    EXPECT_EQ(users.first().sessions, user.sessions);
}

//--------------------------------------------------------------------------------------------------
// A file written before the LDAP settings existed has no section for them, and the import then leaves
// what the host holds as it is.
TEST_F(SettingsUtilTest, MissingLdapSectionLeavesTheSettingsAlone)
{
    const Database::LdapConfig config = ldapConfig();
    ASSERT_TRUE(Database::instance().setLdapConfig(config));

    QFile file(path_);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly));
    file.write(QByteArrayLiteral("{\"system\":{},\"database\":{\"tcp_port\":8050}}"));
    file.close();

    ASSERT_TRUE(SettingsUtil::importFromFile(path_, /* silent */ true));

    const Database::LdapConfig loaded = Database::instance().ldapConfig();
    EXPECT_TRUE(loaded.enabled);
    EXPECT_EQ(loaded.server, config.server);
    EXPECT_EQ(loaded.bind_password, config.bind_password);
    EXPECT_EQ(Database::instance().tcpPort(), 8050);
}
