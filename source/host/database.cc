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

#include <QDir>
#include <QFileInfo>

#include "base/build_config.h"
#include "base/logging.h"
#include "base/crypto/password_generator.h"
#include "base/crypto/password_hash.h"
#include "base/crypto/random.h"
#include "base/crypto/secure_string.h"
#include "base/files/base_paths.h"
#include "base/sql/sql_query.h"
#include "base/sql/sql_transaction.h"

namespace {

const char kSettingSeedKey[] = "seed_key";
const char kSettingTcpPort[] = "tcp_port";
const char kSettingRouterEnabled[] = "router_enabled";
const char kSettingRouterAddress[] = "router_address";
const char kSettingRouterPublicKey[] = "router_public_key";
const char kSettingConnectConfirmation[] = "connect_confirmation";
const char kSettingNoUserAction[] = "no_user_action";
const char kSettingAutoConfirmationInterval[] = "auto_confirmation_interval";
const char kSettingOneTimePassword[] = "one_time_password";
const char kSettingOneTimePasswordExpire[] = "one_time_password_expire";
const char kSettingOneTimePasswordLength[] = "one_time_password_length";
const char kSettingOneTimePasswordCharacters[] = "one_time_password_characters";
const char kSettingHostKey[] = "host_key";
const char kSettingPeerPrivateKey[] = "peer_private_key";
const char kSettingPasswordHash[] = "password_hash";
const char kSettingPasswordHashSalt[] = "password_hash_salt";

const char kSettingLdapEnabled[] = "ldap_enabled";
const char kSettingLdapServer[] = "ldap_server";
const char kSettingLdapPort[] = "ldap_port";
const char kSettingLdapSecurity[] = "ldap_security";
const char kSettingLdapVerifyPeer[] = "ldap_verify_peer";
const char kSettingLdapCaCertificate[] = "ldap_ca_certificate";
const char kSettingLdapBindDn[] = "ldap_bind_dn";
const char kSettingLdapBindPassword[] = "ldap_bind_password";
const char kSettingLdapBaseDn[] = "ldap_base_dn";
const char kSettingLdapUserFilter[] = "ldap_user_filter";
const char kSettingLdapUserNameAttribute[] = "ldap_user_name_attribute";
const char kSettingLdapGroupNested[] = "ldap_group_nested";
const char kSettingLdapGroupBaseDn[] = "ldap_group_base_dn";
const char kSettingLdapGroupFilter[] = "ldap_group_filter";
const char kSettingLdapGroupAttribute[] = "ldap_group_attribute";
const char kSettingLdapDefaultSessions[] = "ldap_default_sessions";
const char kSettingLdapDenyIfUnmapped[] = "ldap_deny_if_unmapped";
const char kSettingLdapAllowLocalFallback[] = "ldap_allow_local_fallback";
const char kSettingLdapCacheTtl[] = "ldap_cache_ttl";

constexpr size_t kPasswordHashSaltSize = 256;

// Set by setFilePathForTesting(). While it is not empty, filePath() and therefore instance() work on
// a test database rather than the host database.
QString g_test_file_path;

//--------------------------------------------------------------------------------------------------
User readUser(const SqlQuery& query)
{
    User user;
    user.entry_id = query.columnInt64(0);
    user.name     = query.columnText(1);
    user.group    = query.columnText(2);
    user.salt     = query.columnBlob(3);
    user.verifier = query.columnBlob(4);
    user.sessions = static_cast<quint32>(query.columnInt64(5));
    user.flags    = static_cast<quint32>(query.columnInt64(6));
    return user;
}

//--------------------------------------------------------------------------------------------------
Database::LdapMapping readMapping(const SqlQuery& query)
{
    Database::LdapMapping mapping;
    mapping.entry_id = query.columnInt64(0);
    mapping.name     = query.columnText(1);
    mapping.sessions = static_cast<quint32>(query.columnInt64(2));
    mapping.flags    = static_cast<quint32>(query.columnInt64(3));
    return mapping;
}

//--------------------------------------------------------------------------------------------------
bool createTables(SqlDatabase& db)
{
    if (!db.exec("CREATE TABLE IF NOT EXISTS \"users\" ("
                 "\"id\" INTEGER UNIQUE,"
                 "\"name\" TEXT NOT NULL UNIQUE,"
                 "\"group\" TEXT NOT NULL,"
                 "\"salt\" BLOB NOT NULL,"
                 "\"verifier\" BLOB NOT NULL,"
                 "\"sessions\" INTEGER DEFAULT 0,"
                 "\"flags\" INTEGER DEFAULT 0,"
                 "PRIMARY KEY(\"id\" AUTOINCREMENT))"))
    {
        LOG(ERROR) << "Unable to create users table:" << db.lastError();
        return false;
    }

    if (!db.exec("CREATE TABLE IF NOT EXISTS \"settings\" ("
                 "\"name\" TEXT PRIMARY KEY NOT NULL,"
                 "\"value\" TEXT NOT NULL)"))
    {
        LOG(ERROR) << "Unable to create settings table:" << db.lastError();
        return false;
    }

    if (!db.exec("CREATE TABLE IF NOT EXISTS \"ldap_groups\" ("
                 "\"id\" INTEGER UNIQUE,"
                 "\"name\" TEXT NOT NULL UNIQUE,"
                 "\"sessions\" INTEGER DEFAULT 0,"
                 "\"flags\" INTEGER DEFAULT 0,"
                 "PRIMARY KEY(\"id\" AUTOINCREMENT))"))
    {
        LOG(ERROR) << "Unable to create ldap_groups table:" << db.lastError();
        return false;
    }

    if (!db.exec("CREATE TABLE IF NOT EXISTS \"ldap_users\" ("
                 "\"id\" INTEGER UNIQUE,"
                 "\"name\" TEXT NOT NULL UNIQUE,"
                 "\"sessions\" INTEGER DEFAULT 0,"
                 "\"flags\" INTEGER DEFAULT 0,"
                 "PRIMARY KEY(\"id\" AUTOINCREMENT))"))
    {
        LOG(ERROR) << "Unable to create ldap_users table:" << db.lastError();
        return false;
    }

    return true;
}

} // namespace

//--------------------------------------------------------------------------------------------------
// static
Database& Database::instance()
{
    static thread_local Database database;

    if (!database.db_.isOpen())
        database.openDatabase();

    return database;
}

//--------------------------------------------------------------------------------------------------
// static
QString Database::directoryPath()
{
    if (!g_test_file_path.isEmpty())
        return QFileInfo(g_test_file_path).absolutePath();

    QString dir_path = BasePaths::appConfigDir();
    if (dir_path.isEmpty())
        return QString();

    return dir_path + "/secure";
}

//--------------------------------------------------------------------------------------------------
// static
QString Database::filePath()
{
    if (!g_test_file_path.isEmpty())
        return g_test_file_path;

    QString dir_path = directoryPath();
    if (dir_path.isEmpty())
        return QString();

    return dir_path + "/host.db3";
}

//--------------------------------------------------------------------------------------------------
// static
void Database::setFilePathForTesting(const QString& file_path)
{
    g_test_file_path = file_path;
    instance().db_.close();
}

//--------------------------------------------------------------------------------------------------
// static
std::unique_ptr<Database> Database::openForTesting(const QString& file_path)
{
    std::unique_ptr<Database> database(new Database());
    if (!database->open(file_path))
        return nullptr;

    return database;
}

//--------------------------------------------------------------------------------------------------
bool Database::isValid() const
{
    return db_.isOpen();
}

//--------------------------------------------------------------------------------------------------
QVector<User> Database::userList() const
{
    if (!isValid())
    {
        LOG(ERROR) << "Database is not valid";
        return {};
    }

    SqlQuery query(db_, "SELECT id, name, \"group\", salt, verifier, sessions, flags FROM users");

    QVector<User> users;
    while (query.next() == SqlQuery::StepResult::ROW)
        users.append(readUser(query));

    return users;
}

//--------------------------------------------------------------------------------------------------
User Database::findUser(const QString& username) const
{
    if (!isValid())
    {
        LOG(ERROR) << "Database is not valid";
        return User::kInvalidUser;
    }

    SqlQuery query(db_,
        "SELECT id, name, \"group\", salt, verifier, sessions, flags FROM users "
        "WHERE casefold(name)=casefold(?)");
    query.addText(username);

    if (query.next() != SqlQuery::StepResult::ROW)
        return User::kInvalidUser;

    return readUser(query);
}

//--------------------------------------------------------------------------------------------------
User Database::findUser(qint64 entry_id) const
{
    if (!isValid())
    {
        LOG(ERROR) << "Database is not valid";
        return User::kInvalidUser;
    }

    SqlQuery query(db_,
        "SELECT id, name, \"group\", salt, verifier, sessions, flags FROM users WHERE id=?");
    query.addInt64(entry_id);

    if (query.next() != SqlQuery::StepResult::ROW)
        return User::kInvalidUser;

    return readUser(query);
}

//--------------------------------------------------------------------------------------------------
bool Database::addUser(const User& user)
{
    if (!isValid())
    {
        LOG(ERROR) << "Database is not valid";
        return false;
    }

    if (!user.isValid())
    {
        LOG(ERROR) << "Not valid user";
        return false;
    }

    // SRP folds the name to lower case before it derives the verifier, so bob and Bob are the
    // same identity to it. The UNIQUE constraint of the column compares bytes and would let both
    // records live, each with its own password and rights.
    SqlQuery name_check(db_, "SELECT 1 FROM users WHERE casefold(name)=casefold(?)");
    name_check.addText(user.name);

    const SqlQuery::StepResult name_step = name_check.next();
    if (name_step == SqlQuery::StepResult::FAILED)
    {
        LOG(ERROR) << "Unable to execute query:" << db_.lastError();
        return false;
    }

    if (name_step == SqlQuery::StepResult::ROW)
    {
        LOG(ERROR) << "User name already exists:" << user.name;
        return false;
    }

    SqlQuery query(db_, "INSERT INTO users (id, name, \"group\", salt, verifier, sessions, flags) "
                        "VALUES (NULL, ?, ?, ?, ?, ?, ?)");
    query.addText(user.name);
    query.addText(user.group);
    query.addBlob(user.salt);
    query.addBlob(user.verifier);
    query.addUInt64(user.sessions);
    query.addUInt64(user.flags);

    if (!query.exec())
    {
        LOG(ERROR) << "Unable to execute query:" << db_.lastError();
        return false;
    }

    return true;
}

//--------------------------------------------------------------------------------------------------
bool Database::modifyUser(const User& user)
{
    if (!isValid())
    {
        LOG(ERROR) << "Database is not valid";
        return false;
    }

    if (!user.isValid())
    {
        LOG(ERROR) << "Not valid user";
        return false;
    }

    // Same reasoning as in addUser. A rename must not take the name of another record, whatever
    // the case it is written in.
    SqlQuery name_check(db_, "SELECT 1 FROM users WHERE casefold(name)=casefold(?) AND id!=?");
    name_check.addText(user.name);
    name_check.addInt64(user.entry_id);

    const SqlQuery::StepResult name_step = name_check.next();
    if (name_step == SqlQuery::StepResult::FAILED)
    {
        LOG(ERROR) << "Unable to execute query:" << db_.lastError();
        return false;
    }

    if (name_step == SqlQuery::StepResult::ROW)
    {
        LOG(ERROR) << "User name already exists:" << user.name;
        return false;
    }

    SqlQuery query(db_, "UPDATE users SET name=?, \"group\"=?, salt=?, verifier=?, sessions=?, "
                        "flags=? WHERE id=?");
    query.addText(user.name);
    query.addText(user.group);
    query.addBlob(user.salt);
    query.addBlob(user.verifier);
    query.addUInt64(user.sessions);
    query.addUInt64(user.flags);
    query.addInt64(user.entry_id);

    if (!query.exec())
    {
        LOG(ERROR) << "Unable to execute query:" << db_.lastError();
        return false;
    }

    return true;
}

//--------------------------------------------------------------------------------------------------
bool Database::removeUser(qint64 entry_id)
{
    if (!isValid())
    {
        LOG(ERROR) << "Database is not valid";
        return false;
    }

    SqlQuery query(db_, "DELETE FROM users WHERE id=?");
    query.addInt64(entry_id);

    if (!query.exec())
    {
        LOG(ERROR) << "Unable to execute query:" << db_.lastError();
        return false;
    }

    return true;
}

//--------------------------------------------------------------------------------------------------
bool Database::replaceUsers(const QVector<User>& users)
{
    if (!isValid())
    {
        LOG(ERROR) << "Database is not valid";
        return false;
    }

    SqlTransaction transaction(db_);
    if (!transaction.begin(SqlTransaction::Mode::IMMEDIATE))
    {
        LOG(ERROR) << "Unable to begin transaction";
        return false;
    }

    // On any failure the early return skips commit(), so the transaction destructor rolls back and the
    // existing user list is preserved.
    SqlQuery query(db_, "DELETE FROM users");
    if (!query.exec())
    {
        LOG(ERROR) << "Unable to execute query:" << db_.lastError();
        return false;
    }

    for (const User& user : users)
    {
        if (!addUser(user))
            return false;
    }

    return transaction.commit();
}

//--------------------------------------------------------------------------------------------------
QByteArray Database::seedKey() const
{
    return QByteArray::fromHex(readSetting(kSettingSeedKey).toLatin1());
}

//--------------------------------------------------------------------------------------------------
bool Database::setSeedKey(const QByteArray& seed_key)
{
    return writeSetting(kSettingSeedKey, QString::fromLatin1(seed_key.toHex()));
}

//--------------------------------------------------------------------------------------------------
quint16 Database::tcpPort() const
{
    bool ok = false;
    uint value = readSetting(kSettingTcpPort).toUInt(&ok);
    if (!ok)
        return kDefaultHostTcpPort;
    return static_cast<quint16>(value);
}

//--------------------------------------------------------------------------------------------------
bool Database::setTcpPort(quint16 port)
{
    return writeSetting(kSettingTcpPort, QString::number(port));
}

//--------------------------------------------------------------------------------------------------
bool Database::isRouterEnabled() const
{
    return readSetting(kSettingRouterEnabled).toInt() != 0;
}

//--------------------------------------------------------------------------------------------------
bool Database::setRouterEnabled(bool enable)
{
    return writeSetting(kSettingRouterEnabled, QString::number(enable ? 1 : 0));
}

//--------------------------------------------------------------------------------------------------
Address Database::routerAddress() const
{
    return Address::fromString(readSetting(kSettingRouterAddress), kDefaultRouterHostTcpPort);
}

//--------------------------------------------------------------------------------------------------
bool Database::setRouterAddress(const Address& address)
{
    return writeSetting(kSettingRouterAddress, address.toString());
}

//--------------------------------------------------------------------------------------------------
QByteArray Database::routerPublicKey() const
{
    return QByteArray::fromHex(readSetting(kSettingRouterPublicKey).toLatin1());
}

//--------------------------------------------------------------------------------------------------
bool Database::setRouterPublicKey(const QByteArray& key)
{
    return writeSetting(kSettingRouterPublicKey, QString::fromLatin1(key.toHex()));
}

//--------------------------------------------------------------------------------------------------
bool Database::connectConfirmation() const
{
    return readSetting(kSettingConnectConfirmation).toInt() != 0;
}

//--------------------------------------------------------------------------------------------------
bool Database::setConnectConfirmation(bool enable)
{
    return writeSetting(kSettingConnectConfirmation, QString::number(enable ? 1 : 0));
}

//--------------------------------------------------------------------------------------------------
Database::NoUserAction Database::noUserAction() const
{
    bool ok = false;
    int value = readSetting(kSettingNoUserAction).toInt(&ok);
    if (!ok)
        return NoUserAction::ACCEPT;
    return static_cast<NoUserAction>(value);
}

//--------------------------------------------------------------------------------------------------
bool Database::setNoUserAction(NoUserAction action)
{
    return writeSetting(kSettingNoUserAction, QString::number(static_cast<int>(action)));
}

//--------------------------------------------------------------------------------------------------
MilliSeconds Database::autoConfirmationInterval() const
{
    static const MilliSeconds kDefaultValue { 0 };
    static const MilliSeconds kMinValue { 0 };
    static const MilliSeconds kMaxValue { 60 * 1000 }; // 60 seconds.

    bool ok = false;
    qint64 value = readSetting(kSettingAutoConfirmationInterval).toLongLong(&ok);
    if (!ok)
        return kDefaultValue;

    MilliSeconds result(value);
    if (result < kMinValue)
        result = kMinValue;
    else if (result > kMaxValue)
        result = kMaxValue;

    return result;
}

//--------------------------------------------------------------------------------------------------
bool Database::setAutoConfirmationInterval(MilliSeconds interval)
{
    return writeSetting(kSettingAutoConfirmationInterval,
                        QString::number(static_cast<qint64>(interval.count())));
}

//--------------------------------------------------------------------------------------------------
bool Database::oneTimePassword() const
{
    QString value = readSetting(kSettingOneTimePassword);
    if (value.isEmpty())
        return true;
    return value.toInt() != 0;
}

//--------------------------------------------------------------------------------------------------
bool Database::setOneTimePassword(bool enable)
{
    return writeSetting(kSettingOneTimePassword, QString::number(enable ? 1 : 0));
}

//--------------------------------------------------------------------------------------------------
MilliSeconds Database::oneTimePasswordExpire() const
{
    static const MilliSeconds kDefaultValue { 5 * 60 * 1000 }; // 5 minutes.
    static const MilliSeconds kMinValue { 0 };
    static const MilliSeconds kMaxValue { 12 * 60 * 60 * 1000 }; // 12 hours.

    bool ok = false;
    qint64 value = readSetting(kSettingOneTimePasswordExpire).toLongLong(&ok);
    if (!ok)
        return kDefaultValue;

    MilliSeconds result(value);
    if (result < kMinValue)
        result = kMinValue;
    else if (result > kMaxValue)
        result = kMaxValue;

    return result;
}

//--------------------------------------------------------------------------------------------------
bool Database::setOneTimePasswordExpire(MilliSeconds interval)
{
    return writeSetting(kSettingOneTimePasswordExpire,
                        QString::number(static_cast<qint64>(interval.count())));
}

//--------------------------------------------------------------------------------------------------
int Database::oneTimePasswordLength() const
{
    static const int kDefaultValue = 8;
    static const int kMinValue = 8;
    static const int kMaxValue = 16;

    bool ok = false;
    int value = readSetting(kSettingOneTimePasswordLength).toInt(&ok);
    if (!ok)
        return kDefaultValue;

    if (value < kMinValue)
        value = kMinValue;
    else if (value > kMaxValue)
        value = kMaxValue;

    return value;
}

//--------------------------------------------------------------------------------------------------
bool Database::setOneTimePasswordLength(int length)
{
    return writeSetting(kSettingOneTimePasswordLength, QString::number(length));
}

//--------------------------------------------------------------------------------------------------
quint32 Database::oneTimePasswordCharacters() const
{
    const quint32 kDefaultValue = PasswordGenerator::DIGITS | PasswordGenerator::LOWER_CASE |
        PasswordGenerator::UPPER_CASE;

    bool ok = false;
    quint32 value = readSetting(kSettingOneTimePasswordCharacters).toUInt(&ok);
    if (!ok)
        return kDefaultValue;

    if (!(value & PasswordGenerator::DIGITS) &&
        !(value & PasswordGenerator::LOWER_CASE) &&
        !(value & PasswordGenerator::UPPER_CASE))
    {
        value = kDefaultValue;
    }

    return value;
}

//--------------------------------------------------------------------------------------------------
bool Database::setOneTimePasswordCharacters(quint32 characters)
{
    return writeSetting(kSettingOneTimePasswordCharacters, QString::number(characters));
}

//--------------------------------------------------------------------------------------------------
QByteArray Database::hostKey() const
{
    return QByteArray::fromHex(readSetting(kSettingHostKey).toLatin1());
}

//--------------------------------------------------------------------------------------------------
bool Database::setHostKey(const QByteArray& key)
{
    return writeSetting(kSettingHostKey, QString::fromLatin1(key.toHex()));
}

//--------------------------------------------------------------------------------------------------
QByteArray Database::peerPrivateKey() const
{
    return QByteArray::fromHex(readSetting(kSettingPeerPrivateKey).toLatin1());
}

//--------------------------------------------------------------------------------------------------
bool Database::setPeerPrivateKey(const QByteArray& key)
{
    return writeSetting(kSettingPeerPrivateKey, QString::fromLatin1(key.toHex()));
}

//--------------------------------------------------------------------------------------------------
Database::PasswordProtection Database::passwordProtectionState() const
{
    if (!isValid())
        return PasswordProtection::UNAVAILABLE;

    SqlTransaction transaction(db_);
    if (!transaction.begin())
    {
        LOG(ERROR) << "Unable to start transaction:" << db_.lastError();
        return PasswordProtection::UNAVAILABLE;
    }

    return (!passwordHash().isEmpty() && !passwordHashSalt().isEmpty()) ?
        PasswordProtection::ENABLED : PasswordProtection::DISABLED;
}

//--------------------------------------------------------------------------------------------------
bool Database::setPassword(const SecureString& password)
{
    if (password.isEmpty())
        return false;

    QByteArray salt = Random::byteArray(kPasswordHashSaltSize);
    if (salt.isEmpty())
        return false;

    QByteArray hash = PasswordHash::hash(PasswordHash::SCRYPT, password, salt);
    if (hash.isEmpty())
        return false;

    SqlTransaction transaction(db_);
    if (!transaction.begin(SqlTransaction::Mode::IMMEDIATE))
    {
        LOG(ERROR) << "Unable to start transaction:" << db_.lastError();
        return false;
    }

    if (!writeSetting(kSettingPasswordHash, QString::fromLatin1(hash.toHex())) ||
        !writeSetting(kSettingPasswordHashSalt, QString::fromLatin1(salt.toHex())))
        return false;

    return transaction.commit();
}

//--------------------------------------------------------------------------------------------------
void Database::clearPassword()
{
    SqlTransaction transaction(db_);
    if (!transaction.begin(SqlTransaction::Mode::IMMEDIATE))
    {
        LOG(ERROR) << "Unable to start transaction:" << db_.lastError();
        return;
    }

    // Commit only if both settings were cleared; a partial clear rolls back so the hash and the
    // salt never go out of sync.
    if (writeSetting(kSettingPasswordHash, QString()) &&
        writeSetting(kSettingPasswordHashSalt, QString()))
    {
        transaction.commit();
    }
}

//--------------------------------------------------------------------------------------------------
bool Database::verifyPassword(const SecureString& password) const
{
    if (password.isEmpty())
        return false;

    QByteArray salt;
    QByteArray hash;

    {
        SqlTransaction transaction(db_);
        if (!transaction.begin())
        {
            LOG(ERROR) << "Unable to start transaction:" << db_.lastError();
            return false;
        }

        salt = passwordHashSalt();
        hash = passwordHash();
    }

    if (salt.isEmpty() || hash.isEmpty())
        return false;

    QByteArray verifiable_hash = PasswordHash::hash(PasswordHash::SCRYPT, password, salt);
    if (verifiable_hash.isEmpty())
        return false;

    return verifiable_hash == hash;
}

//--------------------------------------------------------------------------------------------------
QByteArray Database::passwordHash() const
{
    return QByteArray::fromHex(readSetting(kSettingPasswordHash).toLatin1());
}

//--------------------------------------------------------------------------------------------------
bool Database::setPasswordHash(const QByteArray& hash)
{
    return writeSetting(kSettingPasswordHash, QString::fromLatin1(hash.toHex()));
}

//--------------------------------------------------------------------------------------------------
QByteArray Database::passwordHashSalt() const
{
    return QByteArray::fromHex(readSetting(kSettingPasswordHashSalt).toLatin1());
}

//--------------------------------------------------------------------------------------------------
bool Database::setPasswordHashSalt(const QByteArray& salt)
{
    return writeSetting(kSettingPasswordHashSalt, QString::fromLatin1(salt.toHex()));
}

//--------------------------------------------------------------------------------------------------
bool Database::open(const QString& file_path)
{
    if (file_path.isEmpty())
    {
        LOG(ERROR) << "Invalid file path";
        return false;
    }

    LOG(INFO) << (!QFileInfo::exists(file_path) ? "Creating" : "Opening") << "database:"
              << file_path;

    if (!db_.open(file_path))
        return false;

    if (!db_.exec("PRAGMA secure_delete = ON"))
        LOG(WARNING) << "Unable to enable secure_delete:" << db_.lastError();

    {
        SqlQuery pragma(db_, "PRAGMA quick_check");
        if (pragma.next() == SqlQuery::StepResult::ROW)
        {
            const QString result = pragma.columnText(0);
            if (result != "ok")
                LOG(ERROR) << "Database integrity check failed:" << result;
        }
        else
        {
            LOG(WARNING) << "Unable to run quick_check:" << db_.lastError();
        }
    }

    if (!createTables(db_))
    {
        db_.close();
        return false;
    }

    return true;
}

//--------------------------------------------------------------------------------------------------
bool Database::openDatabase()
{
    QString dir_path = directoryPath();
    if (dir_path.isEmpty())
    {
        LOG(ERROR) << "Invalid directory path";
        return false;
    }

    QFileInfo dir_info(dir_path);
    if (dir_info.exists())
    {
        if (!dir_info.isDir())
        {
            LOG(ERROR) << "Unable to create directory for database. Need to delete file:"
                       << dir_path;
            return false;
        }
    }
    else
    {
        if (!QDir().mkpath(dir_path))
        {
            LOG(ERROR) << "Unable to create directory for database";
            return false;
        }
    }

    QString file_path = filePath();
    if (file_path.isEmpty())
    {
        LOG(ERROR) << "Invalid file path";
        return false;
    }

    return open(file_path);
}

//--------------------------------------------------------------------------------------------------
QString Database::readSetting(const QString& name) const
{
    if (!isValid())
    {
        LOG(ERROR) << "Database is not valid";
        return QString();
    }

    SqlQuery query(db_, "SELECT value FROM settings WHERE name=?");
    query.addText(name);

    if (query.next() != SqlQuery::StepResult::ROW)
        return QString();

    return query.columnText(0);
}

//--------------------------------------------------------------------------------------------------
bool Database::writeSetting(const QString& name, const QString& value)
{
    if (!isValid())
    {
        LOG(ERROR) << "Database is not valid";
        return false;
    }

    SqlQuery query(db_, "INSERT OR REPLACE INTO settings (name, value) VALUES (?, ?)");
    query.addText(name);
    query.addText(value);

    if (!query.exec())
    {
        LOG(ERROR) << "Unable to execute query:" << db_.lastError();
        return false;
    }

    return true;
}

//--------------------------------------------------------------------------------------------------
Database::LdapConfig Database::ldapConfig() const
{
    LdapConfig config;

    const auto read_bool = [this](const char* name, bool default_value)
    {
        const QString value = readSetting(name);
        if (value.isEmpty())
            return default_value;
        return value.toInt() != 0;
    };

    const auto read_string = [this](const char* name, const QString& default_value)
    {
        const QString value = readSetting(name);
        return value.isEmpty() ? default_value : value;
    };

    config.enabled = read_bool(kSettingLdapEnabled, false);
    config.server = read_string(kSettingLdapServer, QString());

    const uint port = read_string(kSettingLdapPort, QStringLiteral("636")).toUInt();
    config.port = static_cast<quint16>(port ? port : 636);

    config.security = static_cast<LdapSecurity>(
        read_string(kSettingLdapSecurity, QStringLiteral("2")).toInt());

    config.verify_peer = read_bool(kSettingLdapVerifyPeer, true);
    config.ca_certificate = read_string(kSettingLdapCaCertificate, QString());
    config.bind_dn = read_string(kSettingLdapBindDn, QString());
    config.bind_password = read_string(kSettingLdapBindPassword, QString());
    config.base_dn = read_string(kSettingLdapBaseDn, QString());
    config.user_filter = read_string(kSettingLdapUserFilter, QString());
    config.user_name_attribute =
        read_string(kSettingLdapUserNameAttribute, QStringLiteral("sAMAccountName"));
    config.group_nested = read_bool(kSettingLdapGroupNested, true);
    config.group_base_dn = read_string(kSettingLdapGroupBaseDn, QString());
    config.group_filter = read_string(kSettingLdapGroupFilter, QString());
    config.group_attribute = read_string(kSettingLdapGroupAttribute, QStringLiteral("cn"));
    config.default_sessions = read_string(kSettingLdapDefaultSessions, QStringLiteral("0")).toUInt();
    config.deny_if_unmapped = read_bool(kSettingLdapDenyIfUnmapped, true);
    config.allow_local_fallback = read_bool(kSettingLdapAllowLocalFallback, true);
    config.cache_ttl = read_string(kSettingLdapCacheTtl, QStringLiteral("60")).toInt();

    return config;
}

//--------------------------------------------------------------------------------------------------
bool Database::setLdapConfig(const LdapConfig& config)
{
    if (!isValid())
    {
        LOG(ERROR) << "Database is not valid";
        return false;
    }

    bool ok = true;

    ok = writeSetting(kSettingLdapEnabled, QString::number(config.enabled ? 1 : 0)) && ok;
    ok = writeSetting(kSettingLdapServer, config.server) && ok;
    ok = writeSetting(kSettingLdapPort, QString::number(config.port)) && ok;
    ok = writeSetting(kSettingLdapSecurity, QString::number(static_cast<int>(config.security))) && ok;
    ok = writeSetting(kSettingLdapVerifyPeer, QString::number(config.verify_peer ? 1 : 0)) && ok;
    ok = writeSetting(kSettingLdapCaCertificate, config.ca_certificate) && ok;
    ok = writeSetting(kSettingLdapBindDn, config.bind_dn) && ok;
    ok = writeSetting(kSettingLdapBindPassword, config.bind_password) && ok;
    ok = writeSetting(kSettingLdapBaseDn, config.base_dn) && ok;
    ok = writeSetting(kSettingLdapUserFilter, config.user_filter) && ok;
    ok = writeSetting(kSettingLdapUserNameAttribute, config.user_name_attribute) && ok;
    ok = writeSetting(kSettingLdapGroupNested, QString::number(config.group_nested ? 1 : 0)) && ok;
    ok = writeSetting(kSettingLdapGroupBaseDn, config.group_base_dn) && ok;
    ok = writeSetting(kSettingLdapGroupFilter, config.group_filter) && ok;
    ok = writeSetting(kSettingLdapGroupAttribute, config.group_attribute) && ok;
    ok = writeSetting(kSettingLdapDefaultSessions, QString::number(config.default_sessions)) && ok;
    ok = writeSetting(kSettingLdapDenyIfUnmapped, QString::number(config.deny_if_unmapped ? 1 : 0)) && ok;
    ok = writeSetting(kSettingLdapAllowLocalFallback, QString::number(config.allow_local_fallback ? 1 : 0)) && ok;
    ok = writeSetting(kSettingLdapCacheTtl, QString::number(config.cache_ttl)) && ok;

    return ok;
}

//--------------------------------------------------------------------------------------------------
QVector<Database::LdapMapping> Database::ldapGroups() const
{
    if (!isValid())
    {
        LOG(ERROR) << "Database is not valid";
        return {};
    }

    SqlQuery query(db_, "SELECT id, name, sessions, flags FROM ldap_groups");

    QVector<LdapMapping> mappings;
    while (query.next() == SqlQuery::StepResult::ROW)
        mappings.append(readMapping(query));

    return mappings;
}

//--------------------------------------------------------------------------------------------------
bool Database::addLdapGroup(const LdapMapping& mapping)
{
    if (!isValid())
    {
        LOG(ERROR) << "Database is not valid";
        return false;
    }

    if (mapping.name.isEmpty())
    {
        LOG(ERROR) << "Empty group name";
        return false;
    }

    SqlQuery query(db_, "INSERT INTO ldap_groups (id, name, sessions, flags) VALUES (NULL, ?, ?, ?)");
    query.addText(mapping.name);
    query.addUInt64(mapping.sessions);
    query.addUInt64(mapping.flags);

    if (!query.exec())
    {
        LOG(ERROR) << "Unable to execute query:" << db_.lastError();
        return false;
    }

    return true;
}

//--------------------------------------------------------------------------------------------------
bool Database::removeLdapGroup(qint64 entry_id)
{
    if (!isValid())
    {
        LOG(ERROR) << "Database is not valid";
        return false;
    }

    SqlQuery query(db_, "DELETE FROM ldap_groups WHERE id=?");
    query.addInt64(entry_id);

    if (!query.exec())
    {
        LOG(ERROR) << "Unable to execute query:" << db_.lastError();
        return false;
    }

    return true;
}

//--------------------------------------------------------------------------------------------------
bool Database::replaceLdapGroups(const QVector<LdapMapping>& mappings)
{
    if (!isValid())
    {
        LOG(ERROR) << "Database is not valid";
        return false;
    }

    SqlTransaction transaction(db_);
    if (!transaction.begin(SqlTransaction::Mode::IMMEDIATE))
    {
        LOG(ERROR) << "Unable to begin transaction:" << db_.lastError();
        return false;
    }

    SqlQuery clear(db_, "DELETE FROM ldap_groups");
    if (!clear.exec())
    {
        LOG(ERROR) << "Unable to execute query:" << db_.lastError();
        return false;
    }

    for (const LdapMapping& mapping : mappings)
    {
        if (!addLdapGroup(mapping))
            return false;
    }

    return transaction.commit();
}

//--------------------------------------------------------------------------------------------------
QVector<Database::LdapMapping> Database::ldapUsers() const
{
    if (!isValid())
    {
        LOG(ERROR) << "Database is not valid";
        return {};
    }

    SqlQuery query(db_, "SELECT id, name, sessions, flags FROM ldap_users");

    QVector<LdapMapping> mappings;
    while (query.next() == SqlQuery::StepResult::ROW)
        mappings.append(readMapping(query));

    return mappings;
}

//--------------------------------------------------------------------------------------------------
bool Database::addLdapUser(const LdapMapping& mapping)
{
    if (!isValid())
    {
        LOG(ERROR) << "Database is not valid";
        return false;
    }

    if (mapping.name.isEmpty())
    {
        LOG(ERROR) << "Empty user name";
        return false;
    }

    SqlQuery query(db_, "INSERT INTO ldap_users (id, name, sessions, flags) VALUES (NULL, ?, ?, ?)");
    query.addText(mapping.name);
    query.addUInt64(mapping.sessions);
    query.addUInt64(mapping.flags);

    if (!query.exec())
    {
        LOG(ERROR) << "Unable to execute query:" << db_.lastError();
        return false;
    }

    return true;
}

//--------------------------------------------------------------------------------------------------
bool Database::removeLdapUser(qint64 entry_id)
{
    if (!isValid())
    {
        LOG(ERROR) << "Database is not valid";
        return false;
    }

    SqlQuery query(db_, "DELETE FROM ldap_users WHERE id=?");
    query.addInt64(entry_id);

    if (!query.exec())
    {
        LOG(ERROR) << "Unable to execute query:" << db_.lastError();
        return false;
    }

    return true;
}

//--------------------------------------------------------------------------------------------------
bool Database::replaceLdapUsers(const QVector<LdapMapping>& mappings)
{
    if (!isValid())
    {
        LOG(ERROR) << "Database is not valid";
        return false;
    }

    SqlTransaction transaction(db_);
    if (!transaction.begin(SqlTransaction::Mode::IMMEDIATE))
    {
        LOG(ERROR) << "Unable to begin transaction:" << db_.lastError();
        return false;
    }

    SqlQuery clear(db_, "DELETE FROM ldap_users");
    if (!clear.exec())
    {
        LOG(ERROR) << "Unable to execute query:" << db_.lastError();
        return false;
    }

    for (const LdapMapping& mapping : mappings)
    {
        if (!addLdapUser(mapping))
            return false;
    }

    return transaction.commit();
}
