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
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QUrl>

#include "base/build_config.h"
#include "base/logging.h"
#include "base/net/address.h"
#include "base/peer/user.h"
#include "host/database.h"
#include "host/system_settings.h"

// The settings dialogs differ per platform, but the imported/exported data does not.
#if defined(Q_OS_ANDROID)
#include "common/android/message_dialog.h"
#else
#include "common/desktop/msg_box.h"
#endif

namespace {

const char kSystem[] = "system";
const char kDatabase[] = "database";

const char kUpdateChannel[] = "update_channel";
const char kPreferredVideoCapturer[] = "preferred_video_capturer";
const char kHardwareVideoEncodingEnabled[] = "hardware_video_encoding_enabled";
const char kApplicationShutdownDisabled[] = "application_shutdown_disabled";
const char kAutoUpdateEnabled[] = "auto_update_enabled";
const char kUpdateCheckFrequency[] = "update_check_frequency";
const char kUpdateServer[] = "update_server";
const char kUpdatePublicKey[] = "update_public_key";

const char kSeedKey[] = "seed_key";
const char kTcpPort[] = "tcp_port";
const char kRouterEnabled[] = "router_enabled";
const char kRouterAddress[] = "router_address";
const char kRouterPublicKey[] = "router_public_key";
const char kConnectConfirmation[] = "connect_confirmation";
const char kNoUserAction[] = "no_user_action";
const char kAutoConfirmationInterval[] = "auto_confirmation_interval";
const char kOneTimePassword[] = "one_time_password";
const char kOneTimePasswordExpire[] = "one_time_password_expire";
const char kOneTimePasswordLength[] = "one_time_password_length";
const char kOneTimePasswordCharacters[] = "one_time_password_characters";
const char kPasswordHash[] = "password_hash";
const char kPasswordHashSalt[] = "password_hash_salt";
const char kUsers[] = "users";

const char kUserName[] = "name";
const char kUserGroup[] = "group";
const char kUserSalt[] = "salt";
const char kUserVerifier[] = "verifier";
const char kUserSessions[] = "sessions";
const char kUserFlags[] = "flags";

// The LDAP settings and the mappings they feed. A file written before they existed has no "ldap"
// object, and the import then leaves what the host holds as it is.
const char kLdap[] = "ldap";

const char kLdapEnabled[] = "enabled";
const char kLdapServer[] = "server";
const char kLdapPort[] = "port";
const char kLdapSecurity[] = "security";
const char kLdapVerifyPeer[] = "verify_peer";
const char kLdapCaCertificate[] = "ca_certificate";
const char kLdapBindDn[] = "bind_dn";
const char kLdapBindPassword[] = "bind_password";
const char kLdapBaseDn[] = "base_dn";
const char kLdapUserFilter[] = "user_filter";
const char kLdapUserNameAttribute[] = "user_name_attribute";
const char kLdapGroupNested[] = "group_nested";
const char kLdapGroupBaseDn[] = "group_base_dn";
const char kLdapGroupFilter[] = "group_filter";
const char kLdapGroupAttribute[] = "group_attribute";
const char kLdapDefaultSessions[] = "default_sessions";
const char kLdapDenyIfUnmapped[] = "deny_if_unmapped";
const char kLdapAllowLocalFallback[] = "allow_local_fallback";
const char kLdapCacheTtl[] = "cache_ttl";

const char kLdapGroups[] = "groups";
const char kLdapUsers[] = "users";

const char kMappingName[] = "name";
const char kMappingSessions[] = "sessions";
const char kMappingFlags[] = "flags";

const int kUpdatePublicKeySize = 32;

//--------------------------------------------------------------------------------------------------
QJsonObject exportSystemSettings()
{
    SystemSettings settings;

    QJsonObject obj;
    obj[kUpdateChannel] = settings.updateChannel();
    obj[kPreferredVideoCapturer] = static_cast<qint64>(settings.preferredVideoCapturer());
    obj[kHardwareVideoEncodingEnabled] = settings.isHardwareVideoEncodingEnabled();
    obj[kApplicationShutdownDisabled] = settings.isApplicationShutdownDisabled();
    obj[kAutoUpdateEnabled] = settings.isAutoUpdateEnabled();
    obj[kUpdateCheckFrequency] = settings.updateCheckFrequency();
    obj[kUpdateServer] = settings.updateServer();
    obj[kUpdatePublicKey] = QString::fromLatin1(settings.updatePublicKey().toHex());
    return obj;
}

//--------------------------------------------------------------------------------------------------
QJsonObject exportLdap()
{
    Database& db = Database::instance();
    const Database::LdapConfig config = db.ldapConfig();

    QJsonObject obj;
    obj[kLdapEnabled] = config.enabled;
    obj[kLdapServer] = config.server;
    obj[kLdapPort] = static_cast<int>(config.port);
    obj[kLdapSecurity] = static_cast<int>(config.security);
    obj[kLdapVerifyPeer] = config.verify_peer;
    obj[kLdapCaCertificate] = config.ca_certificate;
    obj[kLdapBindDn] = config.bind_dn;

    // The password of the service account goes in as it is: the file exists to put the same
    // configuration on another host, and without the password the copy could not bind. The file is a
    // secret for that reason and has to be kept like one.
    obj[kLdapBindPassword] = config.bind_password;

    obj[kLdapBaseDn] = config.base_dn;
    obj[kLdapUserFilter] = config.user_filter;
    obj[kLdapUserNameAttribute] = config.user_name_attribute;
    obj[kLdapGroupNested] = config.group_nested;
    obj[kLdapGroupBaseDn] = config.group_base_dn;
    obj[kLdapGroupFilter] = config.group_filter;
    obj[kLdapGroupAttribute] = config.group_attribute;
    obj[kLdapDefaultSessions] = static_cast<qint64>(config.default_sessions);
    obj[kLdapDenyIfUnmapped] = config.deny_if_unmapped;
    obj[kLdapAllowLocalFallback] = config.allow_local_fallback;
    obj[kLdapCacheTtl] = config.cache_ttl;

    const auto export_mappings = [](const QVector<Database::LdapMapping>& mappings)
    {
        QJsonArray array;

        for (const Database::LdapMapping& mapping : mappings)
        {
            QJsonObject item;
            item[kMappingName] = mapping.name;
            item[kMappingSessions] = static_cast<qint64>(mapping.sessions);
            item[kMappingFlags] = static_cast<qint64>(mapping.flags);
            array.append(item);
        }

        return array;
    };

    obj[kLdapGroups] = export_mappings(db.ldapGroups());
    obj[kLdapUsers] = export_mappings(db.ldapUsers());

    return obj;
}

//--------------------------------------------------------------------------------------------------
QJsonObject exportDatabase()
{
    Database& db = Database::instance();

    QJsonObject obj;
    obj[kSeedKey] = QString::fromLatin1(db.seedKey().toHex());
    obj[kTcpPort] = db.tcpPort();
    obj[kRouterEnabled] = db.isRouterEnabled();
    obj[kRouterAddress] = db.routerAddress().toString();
    obj[kRouterPublicKey] = QString::fromLatin1(db.routerPublicKey().toHex());
    obj[kConnectConfirmation] = db.connectConfirmation();
    obj[kNoUserAction] = static_cast<int>(db.noUserAction());
    obj[kAutoConfirmationInterval] = static_cast<qint64>(db.autoConfirmationInterval().count());
    obj[kOneTimePassword] = db.oneTimePassword();
    obj[kOneTimePasswordExpire] = static_cast<qint64>(db.oneTimePasswordExpire().count());
    obj[kOneTimePasswordLength] = db.oneTimePasswordLength();
    obj[kOneTimePasswordCharacters] = static_cast<qint64>(db.oneTimePasswordCharacters());
    obj[kPasswordHash] = QString::fromLatin1(db.passwordHash().toHex());
    obj[kPasswordHashSalt] = QString::fromLatin1(db.passwordHashSalt().toHex());

    QJsonArray users_array;
    const QVector<User> users = db.userList();
    for (const User& user : users)
    {
        QJsonObject user_obj;
        user_obj[kUserName] = user.name;
        user_obj[kUserGroup] = user.group;
        user_obj[kUserSalt] = QString::fromLatin1(user.salt.toHex());
        user_obj[kUserVerifier] = QString::fromLatin1(user.verifier.toHex());
        user_obj[kUserSessions] = static_cast<qint64>(user.sessions);
        user_obj[kUserFlags] = static_cast<qint64>(user.flags);
        users_array.append(user_obj);
    }
    obj[kUsers] = users_array;
    obj[kLdap] = exportLdap();

    return obj;
}

//--------------------------------------------------------------------------------------------------
void importSystemSettings(const QJsonObject& obj)
{
    SystemSettings settings;

    if (obj.contains(kUpdateChannel))
        settings.setUpdateChannel(obj[kUpdateChannel].toString());
    if (obj.contains(kPreferredVideoCapturer))
        settings.setPreferredVideoCapturer(static_cast<quint32>(obj[kPreferredVideoCapturer].toInteger()));
    if (obj.contains(kHardwareVideoEncodingEnabled))
        settings.setHardwareVideoEncodingEnabled(obj[kHardwareVideoEncodingEnabled].toBool());
    if (obj.contains(kApplicationShutdownDisabled))
        settings.setApplicationShutdownDisabled(obj[kApplicationShutdownDisabled].toBool());
    if (obj.contains(kAutoUpdateEnabled))
        settings.setAutoUpdateEnabled(obj[kAutoUpdateEnabled].toBool());
    if (obj.contains(kUpdateCheckFrequency))
        settings.setUpdateCheckFrequency(obj[kUpdateCheckFrequency].toInt());

    if (obj.contains(kUpdateServer))
    {
        const QString server = obj[kUpdateServer].toString().trimmed();
        const QByteArray key_hex = obj[kUpdatePublicKey].toString().trimmed().toLower().toLatin1();
        const QByteArray key = QByteArray::fromHex(key_hex);

        const QUrl url(server, QUrl::StrictMode);
        const bool server_valid = server.isEmpty() || (url.isValid() && !url.host().isEmpty() &&
            (url.scheme() == "https" || url.scheme() == "http"));
        const bool key_valid = key_hex.isEmpty() ||
            (key.size() == kUpdatePublicKeySize && key.toHex() == key_hex);

        if (!server_valid || !key_valid || (server.isEmpty() && !key.isEmpty()))
        {
            LOG(WARNING) << "Skipping invalid update server:" << server;
        }
        else
        {
            settings.setUpdateServer(server);
            settings.setUpdatePublicKey(key);
        }
    }

    settings.sync();
}

//--------------------------------------------------------------------------------------------------
bool importLdap(const QJsonObject& obj)
{
    Database& db = Database::instance();

    // Starting from what the host holds keeps a file that names only some of the fields from resetting
    // the rest to their defaults.
    Database::LdapConfig config = db.ldapConfig();

    if (obj.contains(kLdapEnabled))
        config.enabled = obj[kLdapEnabled].toBool();
    if (obj.contains(kLdapServer))
        config.server = obj[kLdapServer].toString();
    if (obj.contains(kLdapPort))
        config.port = static_cast<quint16>(obj[kLdapPort].toInt());
    if (obj.contains(kLdapSecurity))
        config.security = static_cast<Database::LdapSecurity>(obj[kLdapSecurity].toInt());
    if (obj.contains(kLdapVerifyPeer))
        config.verify_peer = obj[kLdapVerifyPeer].toBool();
    if (obj.contains(kLdapCaCertificate))
        config.ca_certificate = obj[kLdapCaCertificate].toString();
    if (obj.contains(kLdapBindDn))
        config.bind_dn = obj[kLdapBindDn].toString();
    if (obj.contains(kLdapBindPassword))
        config.bind_password = obj[kLdapBindPassword].toString();
    if (obj.contains(kLdapBaseDn))
        config.base_dn = obj[kLdapBaseDn].toString();
    if (obj.contains(kLdapUserFilter))
        config.user_filter = obj[kLdapUserFilter].toString();
    if (obj.contains(kLdapUserNameAttribute))
        config.user_name_attribute = obj[kLdapUserNameAttribute].toString();
    if (obj.contains(kLdapGroupNested))
        config.group_nested = obj[kLdapGroupNested].toBool();
    if (obj.contains(kLdapGroupBaseDn))
        config.group_base_dn = obj[kLdapGroupBaseDn].toString();
    if (obj.contains(kLdapGroupFilter))
        config.group_filter = obj[kLdapGroupFilter].toString();
    if (obj.contains(kLdapGroupAttribute))
        config.group_attribute = obj[kLdapGroupAttribute].toString();
    if (obj.contains(kLdapDefaultSessions))
        config.default_sessions = static_cast<quint32>(obj[kLdapDefaultSessions].toInteger());
    if (obj.contains(kLdapDenyIfUnmapped))
        config.deny_if_unmapped = obj[kLdapDenyIfUnmapped].toBool();
    if (obj.contains(kLdapAllowLocalFallback))
        config.allow_local_fallback = obj[kLdapAllowLocalFallback].toBool();
    if (obj.contains(kLdapCacheTtl))
        config.cache_ttl = obj[kLdapCacheTtl].toInt();

    if (!db.setLdapConfig(config))
    {
        LOG(ERROR) << "Unable to write the LDAP settings";
        return false;
    }

    const auto import_mappings = [](const QJsonValue& value)
    {
        QVector<Database::LdapMapping> mappings;

        for (const QJsonValue& item_value : value.toArray())
        {
            const QJsonObject item = item_value.toObject();

            Database::LdapMapping mapping;
            mapping.name = item[kMappingName].toString().trimmed();
            mapping.sessions = static_cast<quint32>(item[kMappingSessions].toInteger());
            mapping.flags = item.contains(kMappingFlags)
                ? static_cast<quint32>(item[kMappingFlags].toInteger())
                : static_cast<quint32>(User::ENABLED);

            if (mapping.name.isEmpty())
            {
                LOG(WARNING) << "Skipping an LDAP mapping with no name";
                continue;
            }

            mappings.append(mapping);
        }

        return mappings;
    };

    if (obj.contains(kLdapGroups) && !db.replaceLdapGroups(import_mappings(obj[kLdapGroups])))
    {
        LOG(ERROR) << "Unable to write the LDAP group mappings";
        return false;
    }

    if (obj.contains(kLdapUsers) && !db.replaceLdapUsers(import_mappings(obj[kLdapUsers])))
    {
        LOG(ERROR) << "Unable to write the LDAP user mappings";
        return false;
    }

    return true;
}

//--------------------------------------------------------------------------------------------------
bool importDatabase(const QJsonObject& obj)
{
    Database& db = Database::instance();
    if (!db.isValid())
    {
        LOG(ERROR) << "Database is not valid";
        return false;
    }

    if (obj.contains(kSeedKey))
        db.setSeedKey(QByteArray::fromHex(obj[kSeedKey].toString().toLatin1()));
    if (obj.contains(kTcpPort))
        db.setTcpPort(static_cast<quint16>(obj[kTcpPort].toInt()));
    if (obj.contains(kRouterEnabled))
        db.setRouterEnabled(obj[kRouterEnabled].toBool());
    if (obj.contains(kRouterAddress))
        db.setRouterAddress(Address::fromString(obj[kRouterAddress].toString(), kDefaultRouterHostTcpPort));
    if (obj.contains(kRouterPublicKey))
        db.setRouterPublicKey(QByteArray::fromHex(obj[kRouterPublicKey].toString().toLatin1()));
    if (obj.contains(kConnectConfirmation))
        db.setConnectConfirmation(obj[kConnectConfirmation].toBool());
    if (obj.contains(kNoUserAction))
        db.setNoUserAction(static_cast<Database::NoUserAction>(obj[kNoUserAction].toInt()));
    if (obj.contains(kAutoConfirmationInterval))
        db.setAutoConfirmationInterval(MilliSeconds(obj[kAutoConfirmationInterval].toInteger()));
    if (obj.contains(kOneTimePassword))
        db.setOneTimePassword(obj[kOneTimePassword].toBool());
    if (obj.contains(kOneTimePasswordExpire))
        db.setOneTimePasswordExpire(qMin(MilliSeconds(obj[kOneTimePasswordExpire].toInteger()), MilliSeconds(Hours(12))));
    if (obj.contains(kOneTimePasswordLength))
        db.setOneTimePasswordLength(qMax(obj[kOneTimePasswordLength].toInt(), 8));
    if (obj.contains(kOneTimePasswordCharacters))
        db.setOneTimePasswordCharacters(static_cast<quint32>(obj[kOneTimePasswordCharacters].toInteger()));
    if (obj.contains(kPasswordHash))
        db.setPasswordHash(QByteArray::fromHex(obj[kPasswordHash].toString().toLatin1()));
    if (obj.contains(kPasswordHashSalt))
        db.setPasswordHashSalt(QByteArray::fromHex(obj[kPasswordHashSalt].toString().toLatin1()));

    if (obj.contains(kUsers))
    {
        QVector<User> users;

        const QJsonArray users_array = obj[kUsers].toArray();
        for (const QJsonValue& value : users_array)
        {
            QJsonObject user_obj = value.toObject();

            User user;
            user.name = user_obj[kUserName].toString();
            user.group = user_obj[kUserGroup].toString();
            user.salt = QByteArray::fromHex(user_obj[kUserSalt].toString().toLatin1());
            user.verifier = QByteArray::fromHex(user_obj[kUserVerifier].toString().toLatin1());
            user.sessions = static_cast<quint32>(user_obj[kUserSessions].toInteger());
            user.flags = static_cast<quint32>(user_obj[kUserFlags].toInteger());

            if (!user.isValid())
            {
                LOG(WARNING) << "Skipping invalid user:" << user.name;
                continue;
            }

            users.append(user);
        }

        // Swap the whole list atomically: the old users are only dropped if the new ones are written
        // successfully, so a failed import cannot leave the host with no users.
        if (!db.replaceUsers(users))
        {
            LOG(ERROR) << "Unable to replace user list";
            return false;
        }
    }

    const QJsonObject ldap_obj = obj.value(kLdap).toObject();
    if (!ldap_obj.isEmpty() && !importLdap(ldap_obj))
        return false;

    return true;
}

} // namespace

//--------------------------------------------------------------------------------------------------
// static
bool SettingsUtil::importFromFile(const QString& path, bool silent, QWidget* parent)
{
    LOG(INFO) << "Import settings from" << path;

    if (!QFileInfo::exists(path))
    {
        LOG(ERROR) << "Source settings file does not exist";
        if (!silent)
            showError(parent, tr("Source settings file does not exist."));
        return false;
    }

    QFile file(path);
    if (!file.open(QFile::ReadOnly))
    {
        LOG(ERROR) << "Unable to open source file:" << file.errorString();
        if (!silent)
            showError(parent, tr("Unable to open the source file."));
        return false;
    }

    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(file.readAll(), &error);
    if (doc.isNull() || !doc.isObject())
    {
        LOG(ERROR) << "Failed to parse source file:" << error.errorString();
        if (!silent)
        {
            showError(parent,
                tr("Unable to read the source file: the file is damaged or has an unknown format."));
        }
        return false;
    }

    if (!silent && !confirmOverwrite(parent))
    {
        LOG(INFO) << "Import canceled by user";
        return false;
    }

    QJsonObject root = doc.object();
    importSystemSettings(root.value(kSystem).toObject());

    if (!importDatabase(root.value(kDatabase).toObject()))
    {
        if (!silent)
            showError(parent, tr("Unable to write the secure database."));
        return false;
    }

    if (!silent)
        showInfo(parent, tr("The configuration was successfully imported."));

    return true;
}

//--------------------------------------------------------------------------------------------------
// static
bool SettingsUtil::exportToFile(const QString& path, bool silent, QWidget* parent)
{
    LOG(INFO) << "Export settings to" << path;

    if (!Database::instance().isValid())
    {
        LOG(ERROR) << "Database is not valid";
        if (!silent)
            showError(parent, tr("Unable to read the secure database."));
        return false;
    }

    if (QFileInfo::exists(path) && !silent && !confirmOverwrite(parent))
    {
        LOG(INFO) << "Export canceled by user";
        return false;
    }

    QJsonObject root;
    root[kSystem] = exportSystemSettings();
    root[kDatabase] = exportDatabase();

    const QByteArray json = QJsonDocument(root).toJson(QJsonDocument::Indented);

    QSaveFile file(path);
    if (!file.open(QFile::WriteOnly))
    {
        LOG(ERROR) << "Unable to open target file:" << file.errorString();
        if (!silent)
            showError(parent, tr("Unable to open the target file."));
        return false;
    }

    if (file.write(json) != json.size() || !file.commit())
    {
        LOG(ERROR) << "Failed to write target file:" << file.errorString();
        if (!silent)
            showError(parent, tr("Unable to write the target file."));
        return false;
    }

    if (!silent)
        showInfo(parent, tr("The configuration was successfully exported."));

    return true;
}

//--------------------------------------------------------------------------------------------------
// static
bool SettingsUtil::confirmOverwrite(QWidget* parent)
{
#if defined(Q_OS_ANDROID)
    return MessageDialog::confirm(parent, tr("Warning"),
        tr("The existing settings will be overwritten. Continue?"), tr("Continue"));
#else
    return MsgBox::warning(parent, tr("The existing settings will be overwritten. Continue?"),
                           MsgBox::Yes | MsgBox::No) == MsgBox::Yes;
#endif
}

//--------------------------------------------------------------------------------------------------
// static
void SettingsUtil::showError(QWidget* parent, const QString& text)
{
#if defined(Q_OS_ANDROID)
    MessageDialog::info(parent, tr("Error"), text);
#else
    MsgBox::warning(parent, text);
#endif
}

//--------------------------------------------------------------------------------------------------
// static
void SettingsUtil::showInfo(QWidget* parent, const QString& text)
{
#if defined(Q_OS_ANDROID)
    MessageDialog::info(parent, tr("Aspia"), text);
#else
    MsgBox::information(parent, text);
#endif
}
