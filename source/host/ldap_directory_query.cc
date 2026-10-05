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

#include "host/ldap_directory_query.h"

#include <algorithm>
#include <utility>

#include <QMetaEnum>

#include "base/ldap/ldap_connection.h"
#include "base/ldap/ldap_filter.h"
#include "base/ldap/ldap_group.h"
#include "base/logging.h"
#include "host/ldap_utils.h"

namespace {

//--------------------------------------------------------------------------------------------------
// Adds |name| to |attributes| unless it is already there (compared without regard to case).
void addAttribute(QList<QByteArray>& attributes, const QByteArray& name)
{
    if (name.isEmpty())
        return;

    for (const QByteArray& attribute : std::as_const(attributes))
    {
        if (attribute.compare(name, Qt::CaseInsensitive) == 0)
            return;
    }

    attributes.append(name);
}

} // namespace

//--------------------------------------------------------------------------------------------------
LdapDirectoryQuery::LdapDirectoryQuery(QObject* parent)
    : QObject(parent)
{
}

//--------------------------------------------------------------------------------------------------
LdapDirectoryQuery::~LdapDirectoryQuery() = default;

//--------------------------------------------------------------------------------------------------
void LdapDirectoryQuery::search(const Database::LdapConfig& config, Kind kind)
{
    reset();

    kind_ = kind;
    operation_ = Operation::LIST;

    start(config);
}

//--------------------------------------------------------------------------------------------------
void LdapDirectoryQuery::checkLogin(const Database::LdapConfig& config, const QString& login,
                                    const SecureString& password)
{
    reset();

    login_ = login;
    password_ = password;
    kind_ = Kind::USER;
    operation_ = Operation::CHECK;

    start(config);
}

//--------------------------------------------------------------------------------------------------
void LdapDirectoryQuery::cancel()
{
    reset();
    state_ = State::DONE;
}

//--------------------------------------------------------------------------------------------------
void LdapDirectoryQuery::start(const Database::LdapConfig& config)
{
    config_ = config;

    entries_.clear();
    user_dn_.clear();

    if (config_.server.isEmpty() || config_.base_dn.isEmpty())
    {
        // A request would only time out, so the failure is reported at once instead of making the
        // dialog wait.
        state_ = State::DONE;
        emit sig_failed(tr("Set the server and the user base DN first."));
        return;
    }

    if (operation_ == Operation::CHECK &&
        (config_.user_filter.isEmpty() || !config_.user_filter.contains(QStringLiteral("%1"))))
    {
        // Without the placeholder there is no filter that finds the login to bind as.
        state_ = State::DONE;
        emit sig_failed(tr("The user filter has to contain %1 for the login."));
        return;
    }

    connection_ = new LdapConnection(this);
    connect(connection_, &LdapConnection::sig_connected, this, &LdapDirectoryQuery::onConnected);
    connect(connection_, &LdapConnection::sig_bound, this, &LdapDirectoryQuery::onBound);
    connect(connection_, &LdapConnection::sig_searchEntry, this, &LdapDirectoryQuery::onSearchEntry);
    connect(connection_, &LdapConnection::sig_searchFinished, this,
            &LdapDirectoryQuery::onSearchFinished);
    connect(connection_, &LdapConnection::sig_errorOccurred, this,
            [this](LdapConnection::Error error, const QString& text)
    {
        const QMetaEnum meta_enum = QMetaEnum::fromType<LdapConnection::Error>();

        LOG(WARNING) << "LDAP: the directory could not be reached (error:"
                     << meta_enum.valueToKey(static_cast<int>(error)) << text << ')';

        fail(tr("Could not reach the directory: %1").arg(text));
    });

    connection_->setSecurity(toConnectionSecurity(config_.security));
    connection_->setOperationTimeout(MilliSeconds(10000));

    LdapConnection::TlsOptions tls_options;
    tls_options.verify_peer = config_.verify_peer;
    tls_options.ca_certificate = config_.ca_certificate;
    connection_->setTlsOptions(tls_options);

    state_ = State::CONNECTING;
    connection_->connectToHost(config_.server, config_.port);
}

//--------------------------------------------------------------------------------------------------
void LdapDirectoryQuery::onConnected()
{
    if (state_ != State::CONNECTING)
        return;

    bindService();
}

//--------------------------------------------------------------------------------------------------
void LdapDirectoryQuery::bindService()
{
    state_ = State::BIND_SERVICE;

    // An empty bind DN is an anonymous bind; LdapConnection drops the password in that case.
    connection_->bind(config_.bind_dn.toUtf8(), SecureByteArray(config_.bind_password.toUtf8()));
}

//--------------------------------------------------------------------------------------------------
void LdapDirectoryQuery::onBound(bool success, int result_code, const QString& diagnostic)
{
    switch (state_)
    {
        case State::BIND_SERVICE:
        {
            if (!success)
            {
                if (operation_ == Operation::CHECK)
                {
                    finishCheck(false, result_code, diagnostic);
                }
                else
                {
                    fail(tr("The service bind failed (code %1: %2).").arg(result_code).arg(diagnostic));
                }
                return;
            }

            if (operation_ == Operation::LIST)
                startListSearch();
            else
                startLoginSearch();
        }
        break;

        case State::BIND_USER:
            finishCheck(success, result_code, diagnostic);
            break;

        default:
            break;
    }
}

//--------------------------------------------------------------------------------------------------
void LdapDirectoryQuery::startListSearch()
{
    state_ = State::SEARCH_LIST;
    entries_.clear();

    QString filter;
    QList<QByteArray> attributes;

    if (kind_ == Kind::USER)
    {
        // The search filter says how a login is found; to list everybody the placeholder becomes a
        // wildcard.
        filter = config_.user_filter;
        if (filter.contains(QStringLiteral("%1")))
            filter.replace(QStringLiteral("%1"), QStringLiteral("*"));

        if (filter.isEmpty())
            filter = QStringLiteral("(objectClass=*)");

        addAttribute(attributes, QByteArrayLiteral("displayName"));
        addAttribute(attributes, QByteArrayLiteral("cn"));
        addAttribute(attributes, config_.user_name_attribute.toUtf8());
    }
    else
    {
        filter = config_.group_filter;

        // A directory-agnostic default: the object classes every LDAP directory uses for groups.
        if (filter.isEmpty())
        {
            filter = QStringLiteral("(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)"
                                    "(objectClass=posixGroup)(objectClass=group))");
        }

        addAttribute(attributes, QByteArrayLiteral("cn"));
        addAttribute(attributes, config_.group_attribute.toUtf8());
        addAttribute(attributes, QByteArrayLiteral("description"));
    }

    const QString base = (kind_ == Kind::GROUP && !config_.group_base_dn.isEmpty())
        ? config_.group_base_dn
        : config_.base_dn;

    LOG(INFO) << "LDAP: listing" << (kind_ == Kind::USER ? "users" : "groups")
              << "(base:" << base << "filter:" << filter << ')';

    connection_->search(base.toUtf8(), LdapScope::Subtree, filter, attributes,
                        LdapConnection::kDefaultPageSize);
}

//--------------------------------------------------------------------------------------------------
void LdapDirectoryQuery::startLoginSearch()
{
    state_ = State::SEARCH_LOGIN;
    entries_.clear();

    QString filter = config_.user_filter;
    filter.replace(QStringLiteral("%1"), QString::fromUtf8(ldapEscapeFilterValue(login_)));

    QList<QByteArray> attributes;
    addAttribute(attributes, config_.user_name_attribute.toUtf8());

    LOG(INFO) << "LDAP: searching for the login to check (base:" << config_.base_dn
              << "filter:" << filter << ')';

    connection_->search(config_.base_dn.toUtf8(), LdapScope::Subtree, filter, attributes, 0);
}

//--------------------------------------------------------------------------------------------------
void LdapDirectoryQuery::onSearchEntry(const LdapSearchEntry& entry)
{
    if (state_ == State::SEARCH_LOGIN)
    {
        // The filter is meant to select one object; the first answer is the one to bind as.
        if (user_dn_.isEmpty())
            user_dn_ = QString::fromUtf8(entry.object_name);
        return;
    }

    if (state_ != State::SEARCH_LIST)
        return;

    Entry item;
    item.dn = QString::fromUtf8(entry.object_name);

    if (kind_ == Kind::USER)
    {
        const QList<QByteArray> login = config_.user_name_attribute.isEmpty()
            ? QList<QByteArray>()
            : ldapAttributeValues(entry.attributes, config_.user_name_attribute.toUtf8());

        // Without a login there is nothing to map, so the row would be of no use.
        if (login.isEmpty() || login.first().isEmpty())
            return;

        item.login = QString::fromUtf8(login.first());

        const QList<QByteArray> display_name =
            ldapAttributeValues(entry.attributes, QByteArrayLiteral("displayName"));
        if (!display_name.isEmpty() && !display_name.first().isEmpty())
        {
            item.name = QString::fromUtf8(display_name.first());
        }
        else
        {
            const QList<QByteArray> common_name =
                ldapAttributeValues(entry.attributes, QByteArrayLiteral("cn"));
            item.name = !common_name.isEmpty() && !common_name.first().isEmpty()
                ? QString::fromUtf8(common_name.first())
                : item.login;
        }
    }
    else
    {
        const QString attribute = config_.group_attribute.isEmpty()
            ? QStringLiteral("cn")
            : config_.group_attribute;

        const QList<QByteArray> names = ldapAttributeValues(entry.attributes, attribute.toUtf8());
        if (!names.isEmpty() && !names.first().isEmpty())
        {
            item.name = QString::fromUtf8(names.first());
        }
        else
        {
            const QList<QByteArray> common_name =
                ldapAttributeValues(entry.attributes, QByteArrayLiteral("cn"));
            item.name = !common_name.isEmpty() && !common_name.first().isEmpty()
                ? QString::fromUtf8(common_name.first())
                : QString::fromUtf8(ldapNameFromDn(entry.object_name));
        }

        const QList<QByteArray> description =
            ldapAttributeValues(entry.attributes, QByteArrayLiteral("description"));
        if (!description.isEmpty())
            item.description = QString::fromUtf8(description.first());
    }

    if (!item.name.isEmpty())
        entries_.append(item);
}

//--------------------------------------------------------------------------------------------------
void LdapDirectoryQuery::onSearchFinished(bool success, int result_code, const QString& diagnostic)
{
    switch (state_)
    {
        case State::SEARCH_LIST:
        {
            // A directory that caps a listing (Active Directory answers sizeLimitExceeded and sends
            // up to its limit) still gives a usable list, so the entries that did arrive are shown
            // rather than the dialog failing outright.
            if (!success && result_code != 4 /* sizeLimitExceeded */)
            {
                fail(tr("The search failed (code %1: %2).").arg(result_code).arg(diagnostic));
                return;
            }

            if (!success)
            {
                LOG(WARNING) << "LDAP: the listing hit the server size limit; showing"
                             << entries_.size() << "entries";
            }

            finishList();
        }
        break;

        case State::SEARCH_LOGIN:
        {
            if (!success)
            {
                finishCheck(false, result_code, diagnostic);
                return;
            }

            if (user_dn_.isEmpty())
            {
                // The filter matched nothing: there is no login to bind as.
                finishCheck(false, kLoginNotFound, QString());
                return;
            }

            bindUser();
        }
        break;

        default:
            break;
    }
}

//--------------------------------------------------------------------------------------------------
void LdapDirectoryQuery::bindUser()
{
    state_ = State::BIND_USER;

    LOG(INFO) << "LDAP: binding as the login to check it (dn:" << user_dn_ << ')';

    connection_->bind(user_dn_.toUtf8(), password_.toUtf8());
}

//--------------------------------------------------------------------------------------------------
void LdapDirectoryQuery::finishList()
{
    state_ = State::DONE;

    if (connection_)
        connection_->close();

    std::sort(entries_.begin(), entries_.end(), [](const Entry& first, const Entry& second)
    {
        return first.name.compare(second.name, Qt::CaseInsensitive) < 0;
    });

    LOG(INFO) << "LDAP: the directory listed" << entries_.size()
              << (kind_ == Kind::USER ? "users" : "groups");

    emit sig_entriesFound(entries_);
}

//--------------------------------------------------------------------------------------------------
void LdapDirectoryQuery::finishCheck(bool success, int result_code, const QString& diagnostic)
{
    state_ = State::DONE;

    if (connection_)
        connection_->close();

    LOG(INFO) << "LDAP: the bind check finished (success:" << success << "code:" << result_code
              << "dn:" << user_dn_ << ')';

    emit sig_loginChecked(success, result_code, diagnostic, user_dn_);
}

//--------------------------------------------------------------------------------------------------
void LdapDirectoryQuery::fail(const QString& message)
{
    state_ = State::DONE;

    if (connection_)
        connection_->close();

    LOG(WARNING) << "LDAP: the directory query failed:" << message;

    emit sig_failed(message);
}

//--------------------------------------------------------------------------------------------------
void LdapDirectoryQuery::reset()
{
    if (connection_)
    {
        connection_->close();
        connection_->deleteLater();
        connection_ = nullptr;
    }

    state_ = State::IDLE;
    operation_ = Operation::NONE;
    entries_.clear();
    user_dn_.clear();
}
