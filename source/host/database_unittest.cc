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

#include "host/database.h"

#include <QTemporaryDir>

#include <gtest/gtest.h>

#include "base/build_config.h"
#include "base/crypto/password_generator.h"
#include "base/crypto/secure_string.h"

namespace {

const SecureString kPassword("s3cret-password");

} // namespace

// The secure storage of the host against a real database in a temporary directory. Nothing here
// touches the machine-wide file the service uses.
class HostDatabaseTest : public testing::Test
{
protected:
    void SetUp() override
    {
        ASSERT_TRUE(temp_dir_.isValid());

        db_ = Database::openForTesting(temp_dir_.path() + "/host.db3");
        ASSERT_TRUE(db_);
        ASSERT_TRUE(db_->isValid());
    }

    static User user(const QString& name)
    {
        return User::create(name, SecureString("password"));
    }

    QTemporaryDir temp_dir_;
    std::unique_ptr<Database> db_;
};

//--------------------------------------------------------------------------------------------------
// A user comes back as it was stored and is found both by name and by the id it was given.
TEST_F(HostDatabaseTest, StoredUserIsFoundByNameAndById)
{
    const User stored = user("john");
    ASSERT_TRUE(db_->addUser(stored));

    const User by_name = db_->findUser(QString("john"));
    ASSERT_TRUE(by_name.isValid());
    EXPECT_EQ(by_name.name, stored.name);
    EXPECT_EQ(by_name.salt, stored.salt);
    EXPECT_EQ(by_name.verifier, stored.verifier);
    EXPECT_GT(by_name.entry_id, 0);

    const User by_id = db_->findUser(by_name.entry_id);
    ASSERT_TRUE(by_id.isValid());
    EXPECT_EQ(by_id.name, stored.name);
}

//--------------------------------------------------------------------------------------------------
// Names are what the peer authenticates with, so two users cannot share one.
TEST_F(HostDatabaseTest, UserNameIsTaken)
{
    ASSERT_TRUE(db_->addUser(user("john")));

    EXPECT_FALSE(db_->addUser(user("john")));
    EXPECT_EQ(db_->userList().size(), 1);
}

//--------------------------------------------------------------------------------------------------
// SRP folds the user name to lower case before it derives the verifier, so records differing only
// in case would be one identity with two passwords. The database refuses the second one and finds
// the first whatever case the peer connects with.
TEST_F(HostDatabaseTest, UserNamesAreCaseFolded)
{
    ASSERT_TRUE(db_->addUser(user("john")));
    EXPECT_FALSE(db_->addUser(user("JoHn")));

    const User found = db_->findUser(QString("JOHN"));
    ASSERT_TRUE(found.isValid());
    EXPECT_EQ(found.name, "john");

    // A rename cannot take the folded name of somebody else either.
    ASSERT_TRUE(db_->addUser(user("mary")));

    User mary = db_->findUser(QString("mary"));
    ASSERT_TRUE(mary.isValid());
    mary.name = "JOHN";
    EXPECT_FALSE(db_->modifyUser(mary));
}

//--------------------------------------------------------------------------------------------------
// A user without a name or without a verifier is not a user, and the storage refuses it instead of
// keeping a record nobody can authenticate against.
TEST_F(HostDatabaseTest, IncompleteUserIsRefused)
{
    EXPECT_FALSE(db_->addUser(User()));
    EXPECT_FALSE(db_->modifyUser(User()));
    EXPECT_TRUE(db_->userList().isEmpty());
}

//--------------------------------------------------------------------------------------------------
// An edit reaches the record the id points at and leaves the rest alone.
TEST_F(HostDatabaseTest, UserIsModifiedInPlace)
{
    ASSERT_TRUE(db_->addUser(user("john")));
    ASSERT_TRUE(db_->addUser(user("mary")));

    User john = db_->findUser(QString("john"));
    ASSERT_TRUE(john.isValid());

    john.sessions = 3;
    john.flags = User::ENABLED;
    ASSERT_TRUE(db_->modifyUser(john));

    const User reread = db_->findUser(john.entry_id);
    ASSERT_TRUE(reread.isValid());
    EXPECT_EQ(reread.sessions, 3u);
    EXPECT_EQ(reread.flags, static_cast<quint32>(User::ENABLED));

    EXPECT_EQ(db_->findUser(QString("mary")).sessions, 0u);
}

//--------------------------------------------------------------------------------------------------
// A removed user cannot authenticate anymore.
TEST_F(HostDatabaseTest, RemovedUserIsGone)
{
    ASSERT_TRUE(db_->addUser(user("john")));
    const User john = db_->findUser(QString("john"));
    ASSERT_TRUE(john.isValid());

    EXPECT_TRUE(db_->removeUser(john.entry_id));
    EXPECT_FALSE(db_->findUser(QString("john")).isValid());
    EXPECT_TRUE(db_->userList().isEmpty());
}

//--------------------------------------------------------------------------------------------------
// The import replaces the whole list at once.
TEST_F(HostDatabaseTest, ReplaceUsersSwapsTheWholeList)
{
    ASSERT_TRUE(db_->addUser(user("john")));

    QVector<User> users;
    users.append(user("mary"));
    users.append(user("paul"));

    ASSERT_TRUE(db_->replaceUsers(users));

    EXPECT_EQ(db_->userList().size(), 2);
    EXPECT_FALSE(db_->findUser(QString("john")).isValid());
    EXPECT_TRUE(db_->findUser(QString("mary")).isValid());
    EXPECT_TRUE(db_->findUser(QString("paul")).isValid());
}

//--------------------------------------------------------------------------------------------------
// An import that cannot be carried out to the end leaves the users that were there. A half applied
// import is a host nobody can connect to.
TEST_F(HostDatabaseTest, FailedReplaceKeepsTheStoredUsers)
{
    ASSERT_TRUE(db_->addUser(user("john")));

    QVector<User> users;
    users.append(user("mary"));
    users.append(User());

    EXPECT_FALSE(db_->replaceUsers(users));

    ASSERT_EQ(db_->userList().size(), 1);
    EXPECT_TRUE(db_->findUser(QString("john")).isValid());
}

//--------------------------------------------------------------------------------------------------
// A fresh database answers with the defaults of the host instead of empty values.
TEST_F(HostDatabaseTest, FreshDatabaseAnswersWithDefaults)
{
    EXPECT_EQ(db_->tcpPort(), kDefaultHostTcpPort);
    EXPECT_FALSE(db_->isRouterEnabled());
    EXPECT_TRUE(db_->oneTimePassword());
    EXPECT_EQ(db_->oneTimePasswordExpire(), Minutes(5));
    EXPECT_EQ(db_->oneTimePasswordLength(), 8);
    EXPECT_EQ(db_->autoConfirmationInterval(), MilliSeconds(0));
    EXPECT_EQ(db_->passwordProtectionState(), Database::PasswordProtection::DISABLED);
    EXPECT_TRUE(db_->seedKey().isEmpty());
    EXPECT_TRUE(db_->hostKey().isEmpty());
}

//--------------------------------------------------------------------------------------------------
// Settings come back as they were written, including the ones stored as hex.
TEST_F(HostDatabaseTest, SettingsSurviveAWriteAndRead)
{
    Address address(kDefaultRouterHostTcpPort);
    address.setHost("router.example.com");
    address.setPort(8061);

    // All of them are stored as hex, so they are binary on purpose: zero bytes and everything above
    // the ascii range have to survive the trip.
    const QByteArray key("\x00\x01\xfe\xff public key", 15);
    const QByteArray seed("\x00\xaa\xbb seed", 8);
    const QByteArray host_key("\x00\xcc\xdd host key", 12);

    ASSERT_TRUE(db_->setTcpPort(9999));
    ASSERT_TRUE(db_->setRouterEnabled(true));
    ASSERT_TRUE(db_->setRouterAddress(address));
    ASSERT_TRUE(db_->setRouterPublicKey(key));
    ASSERT_TRUE(db_->setSeedKey(seed));
    ASSERT_TRUE(db_->setHostKey(host_key));
    ASSERT_TRUE(db_->setConnectConfirmation(true));
    ASSERT_TRUE(db_->setNoUserAction(Database::NoUserAction::ACCEPT));

    EXPECT_EQ(db_->tcpPort(), 9999);
    EXPECT_TRUE(db_->isRouterEnabled());
    EXPECT_EQ(db_->routerAddress(), address);
    EXPECT_EQ(db_->routerPublicKey(), key);
    EXPECT_EQ(db_->seedKey(), seed);
    EXPECT_EQ(db_->hostKey(), host_key);
    EXPECT_TRUE(db_->connectConfirmation());
    EXPECT_EQ(db_->noUserAction(), Database::NoUserAction::ACCEPT);
}

//--------------------------------------------------------------------------------------------------
// The values that drive the one-time password are read back inside the bounds the host works with,
// whatever ended up in the file.
TEST_F(HostDatabaseTest, OneTimePasswordSettingsAreKeptInBounds)
{
    ASSERT_TRUE(db_->setOneTimePasswordExpire(Hours(48)));
    EXPECT_EQ(db_->oneTimePasswordExpire(), Hours(12));

    ASSERT_TRUE(db_->setOneTimePasswordExpire(MilliSeconds(-1)));
    EXPECT_EQ(db_->oneTimePasswordExpire(), MilliSeconds(0));

    ASSERT_TRUE(db_->setOneTimePasswordLength(2));
    EXPECT_EQ(db_->oneTimePasswordLength(), 8);

    ASSERT_TRUE(db_->setOneTimePasswordLength(100));
    EXPECT_EQ(db_->oneTimePasswordLength(), 16);

    // A password of no characters at all cannot be generated, so the stored value gives way to the
    // default set.
    ASSERT_TRUE(db_->setOneTimePasswordCharacters(0));
    EXPECT_NE(db_->oneTimePasswordCharacters(), 0u);

    ASSERT_TRUE(db_->setOneTimePasswordCharacters(PasswordGenerator::DIGITS));
    EXPECT_EQ(db_->oneTimePasswordCharacters(),
              static_cast<quint32>(PasswordGenerator::DIGITS));

    ASSERT_TRUE(db_->setAutoConfirmationInterval(Minutes(5)));
    EXPECT_EQ(db_->autoConfirmationInterval(), Seconds(60));
}

//--------------------------------------------------------------------------------------------------
// The password that guards the settings is stored as a hash and verified against it.
TEST_F(HostDatabaseTest, PasswordProtectionIsSetAndVerified)
{
    ASSERT_TRUE(db_->setPassword(kPassword));
    EXPECT_EQ(db_->passwordProtectionState(), Database::PasswordProtection::ENABLED);

    EXPECT_TRUE(db_->verifyPassword(kPassword));
    EXPECT_FALSE(db_->verifyPassword(SecureString("s3cret-passwor")));
    EXPECT_FALSE(db_->verifyPassword(SecureString()));
}

//--------------------------------------------------------------------------------------------------
// Clearing the protection leaves nothing that could still be verified against.
TEST_F(HostDatabaseTest, ClearedPasswordVerifiesAgainstNothing)
{
    ASSERT_TRUE(db_->setPassword(kPassword));

    db_->clearPassword();

    EXPECT_EQ(db_->passwordProtectionState(), Database::PasswordProtection::DISABLED);
    EXPECT_FALSE(db_->verifyPassword(kPassword));
}

//--------------------------------------------------------------------------------------------------
// The protection is carried to another host as the stored hash and its salt, and the password
// still verifies against them there.
TEST_F(HostDatabaseTest, PasswordHashIsCarriedToAnotherDatabase)
{
    ASSERT_TRUE(db_->setPassword(kPassword));

    std::unique_ptr<Database> other = Database::openForTesting(temp_dir_.path() + "/other.db3");
    ASSERT_TRUE(other);
    ASSERT_TRUE(other->setPasswordHash(db_->passwordHash()));
    ASSERT_TRUE(other->setPasswordHashSalt(db_->passwordHashSalt()));

    EXPECT_EQ(other->passwordProtectionState(), Database::PasswordProtection::ENABLED);
    EXPECT_TRUE(other->verifyPassword(kPassword));
    EXPECT_FALSE(other->verifyPassword(SecureString("s3cret-passwor")));
}

//--------------------------------------------------------------------------------------------------
// An empty password would protect nothing, so it is refused and what was there stays.
TEST_F(HostDatabaseTest, EmptyPasswordIsRefused)
{
    ASSERT_TRUE(db_->setPassword(kPassword));

    EXPECT_FALSE(db_->setPassword(SecureString()));

    EXPECT_EQ(db_->passwordProtectionState(), Database::PasswordProtection::ENABLED);
    EXPECT_TRUE(db_->verifyPassword(kPassword));
}

//--------------------------------------------------------------------------------------------------
// The same password gets its own salt every time, so two hosts with one password do not share a
// hash.
TEST_F(HostDatabaseTest, PasswordIsSaltedAnew)
{
    ASSERT_TRUE(db_->setPassword(kPassword));

    std::unique_ptr<Database> other = Database::openForTesting(temp_dir_.path() + "/other.db3");
    ASSERT_TRUE(other);
    ASSERT_TRUE(other->setPassword(kPassword));

    EXPECT_TRUE(other->verifyPassword(kPassword));
}

//--------------------------------------------------------------------------------------------------
// What was written stays in the file and is there for the next connection to the same database.
TEST_F(HostDatabaseTest, ContentsSurviveReopening)
{
    ASSERT_TRUE(db_->addUser(user("john")));
    ASSERT_TRUE(db_->setTcpPort(9999));
    ASSERT_TRUE(db_->setPassword(kPassword));

    db_.reset();

    std::unique_ptr<Database> reopened = Database::openForTesting(temp_dir_.path() + "/host.db3");
    ASSERT_TRUE(reopened);

    EXPECT_TRUE(reopened->findUser(QString("john")).isValid());
    EXPECT_EQ(reopened->tcpPort(), 9999);
    EXPECT_TRUE(reopened->verifyPassword(kPassword));
}

//--------------------------------------------------------------------------------------------------
// The LDAP configuration round-trips through the secure storage; the defaults apply before anything
// is written.
TEST_F(HostDatabaseTest, LdapConfigRoundTrip)
{
    const Database::LdapConfig defaults = db_->ldapConfig();
    EXPECT_FALSE(defaults.enabled);
    EXPECT_EQ(defaults.port, 636);
    EXPECT_EQ(defaults.security, Database::LdapSecurity::STARTTLS);
    EXPECT_TRUE(defaults.verify_peer);
    EXPECT_TRUE(defaults.group_nested);
    EXPECT_EQ(defaults.user_name_attribute, QStringLiteral("sAMAccountName"));
    EXPECT_EQ(defaults.group_attribute, QStringLiteral("cn"));
    EXPECT_TRUE(defaults.deny_if_unmapped);
    EXPECT_TRUE(defaults.allow_local_fallback);
    EXPECT_EQ(defaults.cache_ttl, 60);

    Database::LdapConfig config;
    config.enabled = true;
    config.server = QStringLiteral("ldap.example.com");
    config.port = 1389;
    config.security = Database::LdapSecurity::LDAPS;
    config.verify_peer = false;
    config.ca_certificate = QStringLiteral("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----");
    config.bind_dn = QStringLiteral("cn=service,dc=x");
    config.bind_password = QStringLiteral("bind-secret");
    config.base_dn = QStringLiteral("dc=x");
    config.user_filter = QStringLiteral("(&(objectClass=person)(sAMAccountName=%1))");
    config.user_name_attribute = QStringLiteral("uid");
    config.group_nested = false;
    config.group_base_dn = QStringLiteral("ou=groups,dc=x");
    config.group_filter = QStringLiteral("(objectClass=group)");
    config.group_attribute = QStringLiteral("cn");
    config.default_sessions = 1 | 4;
    config.deny_if_unmapped = false;
    config.allow_local_fallback = false;
    config.cache_ttl = 120;

    ASSERT_TRUE(db_->setLdapConfig(config));

    const Database::LdapConfig loaded = db_->ldapConfig();
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
    EXPECT_FALSE(loaded.group_nested);
    EXPECT_EQ(loaded.group_base_dn, config.group_base_dn);
    EXPECT_EQ(loaded.group_filter, config.group_filter);
    EXPECT_EQ(loaded.group_attribute, config.group_attribute);
    EXPECT_EQ(loaded.default_sessions, config.default_sessions);
    EXPECT_FALSE(loaded.deny_if_unmapped);
    EXPECT_FALSE(loaded.allow_local_fallback);
    EXPECT_EQ(loaded.cache_ttl, config.cache_ttl);
}

//--------------------------------------------------------------------------------------------------
TEST_F(HostDatabaseTest, LdapMappings)
{
    Database::LdapMapping group;
    group.name = QStringLiteral("cn=admins,dc=x");
    group.sessions = 63;
    group.flags = User::ENABLED;
    ASSERT_TRUE(db_->addLdapGroup(group));

    Database::LdapMapping user_mapping;
    user_mapping.name = QStringLiteral("jdoe");
    user_mapping.sessions = 1;
    user_mapping.flags = User::ENABLED;
    ASSERT_TRUE(db_->addLdapUser(user_mapping));

    const QVector<Database::LdapMapping> groups = db_->ldapGroups();
    ASSERT_EQ(groups.size(), 1);
    EXPECT_EQ(groups.at(0).name, group.name);
    EXPECT_EQ(groups.at(0).sessions, 63u);
    EXPECT_GT(groups.at(0).entry_id, 0);

    const QVector<Database::LdapMapping> users = db_->ldapUsers();
    ASSERT_EQ(users.size(), 1);
    EXPECT_EQ(users.at(0).name, QStringLiteral("jdoe"));

    ASSERT_TRUE(db_->removeLdapGroup(groups.at(0).entry_id));
    EXPECT_TRUE(db_->ldapGroups().isEmpty());

    ASSERT_TRUE(db_->replaceLdapUsers({ user_mapping }));
    EXPECT_EQ(db_->ldapUsers().size(), 1);
}

//--------------------------------------------------------------------------------------------------
// The host's long-term peer key round-trips through the secure storage.
TEST_F(HostDatabaseTest, PeerPrivateKeyRoundTrip)
{
    EXPECT_TRUE(db_->peerPrivateKey().isEmpty());

    const QByteArray key("\x00\x01\xfe private key", 15);
    ASSERT_TRUE(db_->setPeerPrivateKey(key));
    EXPECT_EQ(db_->peerPrivateKey(), key);
}
