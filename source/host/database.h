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

#ifndef HOST_DATABASE_H
#define HOST_DATABASE_H

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QVector>

#include <memory>

#include "base/time_types.h"
#include "base/net/address.h"
#include "base/peer/user.h"
#include "base/sql/sql_database.h"

class SecureString;

// Host secure storage. Readable and writable only by SYSTEM and elevated administrators
// (root on POSIX); regular users cannot read or write its contents through any path,
// including direct file access.
class Database
{
    Q_GADGET

public:
    enum class PasswordProtection
    {
        DISABLED,   // No password hash stored in the database.
        ENABLED,    // Password hash stored.
        UNAVAILABLE // Database is invalid or not readable.
    };
    Q_ENUM(PasswordProtection)

    enum class NoUserAction
    {
        ACCEPT = 0,
        REJECT = 1
    };
    Q_ENUM(NoUserAction)

    ~Database() = default;

    static Database& instance();
    static QString directoryPath();
    static QString filePath();

    // Opens (creating when absent) an isolated database at |file_path| and ensures the schema.
    // Only for the tests; production code goes through instance(), which owns the per-thread
    // connection at filePath(). Returns nothing when the file cannot be opened.
    static std::unique_ptr<Database> openForTesting(const QString& file_path);

    bool isValid() const;

    // Users.
    QVector<User> userList() const;
    User findUser(const QString& username) const;
    User findUser(qint64 entry_id) const;
    bool addUser(const User& user);
    bool modifyUser(const User& user);
    bool removeUser(qint64 entry_id);
    bool replaceUsers(const QVector<User>& users);

    // Settings.
    QByteArray seedKey() const;
    bool setSeedKey(const QByteArray& seed_key);

    quint16 tcpPort() const;
    bool setTcpPort(quint16 port);

    bool isRouterEnabled() const;
    bool setRouterEnabled(bool enable);

    Address routerAddress() const;
    bool setRouterAddress(const Address& address);

    QByteArray routerPublicKey() const;
    bool setRouterPublicKey(const QByteArray& key);

    bool connectConfirmation() const;
    bool setConnectConfirmation(bool enable);

    NoUserAction noUserAction() const;
    bool setNoUserAction(NoUserAction action);

    MilliSeconds autoConfirmationInterval() const;
    bool setAutoConfirmationInterval(MilliSeconds interval);

    bool oneTimePassword() const;
    bool setOneTimePassword(bool enable);

    MilliSeconds oneTimePasswordExpire() const;
    bool setOneTimePasswordExpire(MilliSeconds interval);

    int oneTimePasswordLength() const;
    bool setOneTimePasswordLength(int length);

    quint32 oneTimePasswordCharacters() const;
    bool setOneTimePasswordCharacters(quint32 characters);

    // Host key.
    QByteArray hostKey() const;
    bool setHostKey(const QByteArray& key);

    // Long-term private key the host uses to authenticate itself to direct clients (the password
    // method, IDENTIFY_PASSWORD). Stored in the root-only database like the other secrets.
    QByteArray peerPrivateKey() const;
    bool setPeerPrivateKey(const QByteArray& key);

    // Password protection.
    PasswordProtection passwordProtectionState() const;
    bool setPassword(const SecureString& password);
    void clearPassword();
    bool verifyPassword(const SecureString& password) const;
    QByteArray passwordHash() const;
    bool setPasswordHash(const QByteArray& hash);
    QByteArray passwordHashSalt() const;
    bool setPasswordHashSalt(const QByteArray& salt);

    // LDAP authentication.
    enum class LdapSecurity
    {
        PLAIN = 0,   // No transport encryption.
        LDAPS = 1,   // TLS from the first byte.
        STARTTLS = 2 // Plaintext, then upgraded via StartTLS.
    };
    Q_ENUM(LdapSecurity)

    struct LdapConfig
    {
        bool enabled = false;
        QString server;
        quint16 port = 636;
        LdapSecurity security = LdapSecurity::STARTTLS;
        bool verify_peer = true;
        QString ca_certificate;      // The certificate of the CA, PEM encoded.
        QString bind_dn;
        QString bind_password;
        QString base_dn;             // User search base.
        QString user_filter;         // RFC 4515 filter with a %1 placeholder for the login.
        QString user_name_attribute; // Attribute that carries the login (e.g. sAMAccountName).
        bool group_nested = true;    // Use the AD matching rule in chain for nested groups.
        QString group_base_dn;
        QString group_filter;
        QString group_attribute;     // The attribute that names a group (cn).
        quint32 default_sessions = 0;
        bool deny_if_unmapped = true;
        bool allow_local_fallback = true; // LDAP preferred vs LDAP only.
        int cache_ttl = 60; // Seconds a resolution is cached for; 0 disables the cache.
    };

    // A group or user mapping: how the matching identity maps to the host permission bitmask.
    struct LdapMapping
    {
        qint64 entry_id = 0;
        QString name;      // Group DN/name, or LDAP user name.
        quint32 sessions = 0;
        quint32 flags = 0; // User::Flags.
    };

    LdapConfig ldapConfig() const;
    bool setLdapConfig(const LdapConfig& config);

    QVector<LdapMapping> ldapGroups() const;
    bool addLdapGroup(const LdapMapping& mapping);
    bool removeLdapGroup(qint64 entry_id);
    bool replaceLdapGroups(const QVector<LdapMapping>& mappings);

    QVector<LdapMapping> ldapUsers() const;
    bool addLdapUser(const LdapMapping& mapping);
    bool removeLdapUser(qint64 entry_id);
    bool replaceLdapUsers(const QVector<LdapMapping>& mappings);

private:
    friend class DatabaseTestPeer;

    Database() = default;

    // Points the per-thread connection of instance() at |file_path| and closes the previous
    // connection, so a test works on a database of its own instead of the host database.
    static void setFilePathForTesting(const QString& file_path);

    bool open(const QString& file_path);
    bool openDatabase();

    QString readSetting(const QString& name) const;
    bool writeSetting(const QString& name, const QString& value);

    mutable SqlDatabase db_;

    Q_DISABLE_COPY(Database)
};

#endif // HOST_DATABASE_H
