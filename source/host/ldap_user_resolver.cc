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

#include "host/ldap_user_resolver.h"

#include <QMetaEnum>

#include "base/ldap/ldap_connection.h"
#include "base/ldap/ldap_filter.h"
#include "base/ldap/ldap_group.h"
#include "base/logging.h"
#include "host/ldap_utils.h"

namespace {

//--------------------------------------------------------------------------------------------------
// The name of the group an entry stands for: the attribute the settings name (cn in every directory),
// or the first RDN of its DN when that attribute came back empty.
QString groupNameOf(const LdapSearchEntry& entry, const QString& attribute)
{
    const QList<QByteArray> names = ldapAttributeValues(entry.attributes, attribute.toUtf8());
    if (!names.isEmpty() && !names.first().isEmpty())
        return QString::fromUtf8(names.first());

    return QString::fromUtf8(ldapNameFromDn(entry.object_name));
}

// A directory that keeps handing out memberOf in ranges would be read forever; this many slices end
// it, with the groups that did arrive. At the Active Directory slice size it is far beyond any real
// membership.
constexpr int kMaxMemberRangeSlices = 1000;

} // namespace

//--------------------------------------------------------------------------------------------------
quint32 ldapMapSessions(const QVector<Database::LdapMapping>& group_mappings,
                        const QVector<Database::LdapMapping>& user_mappings,
                        const QString& login, const QStringList& group_dns,
                        quint32 default_sessions, bool deny_if_unmapped, bool* matched)
{
    quint32 sessions = 0;
    bool any = false;

    // Every matching source only adds rights; the highest privilege wins.
    for (const Database::LdapMapping& mapping : group_mappings)
    {
        for (const QString& group_dn : group_dns)
        {
            if (mapping.name.compare(group_dn, Qt::CaseInsensitive) == 0)
            {
                sessions |= mapping.sessions;
                any = true;
                break;
            }
        }
    }

    for (const Database::LdapMapping& mapping : user_mappings)
    {
        if (mapping.name.compare(login, Qt::CaseInsensitive) == 0)
        {
            sessions |= mapping.sessions;
            any = true;
        }
    }

    if (matched)
        *matched = any;

    if (!any)
        return deny_if_unmapped ? 0 : default_sessions;

    return sessions;
}

//--------------------------------------------------------------------------------------------------
LdapUserResolver::LdapUserResolver(QObject* parent)
    : QObject(parent)
{
    // The connection is created per resolve().
}

//--------------------------------------------------------------------------------------------------
LdapUserResolver::~LdapUserResolver() = default;

//--------------------------------------------------------------------------------------------------
void LdapUserResolver::setConfig(const Database::LdapConfig& config)
{
    config_ = config;
}

//--------------------------------------------------------------------------------------------------
void LdapUserResolver::setMappings(const QVector<Database::LdapMapping>& groups,
                                   const QVector<Database::LdapMapping>& users)
{
    group_mappings_ = groups;
    user_mappings_ = users;
}

//--------------------------------------------------------------------------------------------------
void LdapUserResolver::resolve(const QString& login, const SecureString& password)
{
    reset();

    login_ = login;
    password_ = password;

    if (!config_.enabled || config_.server.isEmpty() || config_.base_dn.isEmpty() ||
        config_.user_filter.isEmpty() || config_.user_name_attribute.isEmpty())
    {
        state_ = State::DONE;
        emit sig_fallbackToLocal();
        return;
    }

    LOG(INFO) << "LDAP: resolving login" << login_ << "on" << config_.server << ':' << config_.port
              << "base:" << config_.base_dn << "filter:" << config_.user_filter
              << "group base:" << config_.group_base_dn << "nested:" << config_.group_nested;

    connection_ = new LdapConnection(this);
    connect(connection_, &LdapConnection::sig_connected, this, &LdapUserResolver::onConnected);
    connect(connection_, &LdapConnection::sig_bound, this, &LdapUserResolver::onBound);
    connect(connection_, &LdapConnection::sig_searchEntry, this, &LdapUserResolver::onSearchEntry);
    connect(connection_, &LdapConnection::sig_searchFinished, this,
            &LdapUserResolver::onSearchFinished);
    connect(connection_, &LdapConnection::sig_errorOccurred, this,
            [this](LdapConnection::Error error, const QString& text)
    {
        // A refused connection, a name that does not resolve and a server that does not answer are
        // told apart here, before the fallback hides the reason.
        const QMetaEnum meta_enum = QMetaEnum::fromType<LdapConnection::Error>();

        LOG(WARNING) << "LDAP: the directory could not be reached (error:"
                     << meta_enum.valueToKey(static_cast<int>(error)) << text << ')';

        onConnectionError();
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
void LdapUserResolver::cancel()
{
    if (connection_)
        connection_->close();

    state_ = State::DONE;
}

//--------------------------------------------------------------------------------------------------
void LdapUserResolver::onConnected()
{
    if (state_ != State::CONNECTING)
        return;

    state_ = State::BIND_SERVICE;
    connection_->bind(config_.bind_dn.toUtf8(), SecureByteArray(config_.bind_password.toUtf8()));
}

//--------------------------------------------------------------------------------------------------
void LdapUserResolver::onBound(bool success, int result_code, const QString& diagnostic)
{
    switch (state_)
    {
        case State::BIND_SERVICE:
        {
            // The service account could not bind: treat LDAP as unusable and fall back to local.
            if (!success)
            {
                LOG(WARNING) << "LDAP: the service bind failed (result:" << result_code
                             << ldapResultCodeName(result_code) << "diagnostic:" << diagnostic << ')';
                fail();
                return;
            }

            LOG(INFO) << "LDAP: the service bind succeeded"
                      << (config_.bind_dn.isEmpty() ? " (anonymous)" : "");

            state_ = State::SEARCH_USER;
            entries_.clear();

            QString filter = config_.user_filter;
            filter.replace(QStringLiteral("%1"),
                           QString::fromUtf8(ldapEscapeFilterValue(login_)));

            LOG(INFO) << "LDAP: searching for the login (base:" << config_.base_dn
                      << "filter:" << filter << ')';

            const QList<QByteArray> attributes = { config_.user_name_attribute.toUtf8(),
                                                   QByteArrayLiteral("memberOf") };

            connection_->search(config_.base_dn.toUtf8(), LdapScope::Subtree, filter, attributes, 0);
        }
        break;

        case State::BIND_USER:
        {
            // The user bind is the password check and is authoritative.
            if (success)
            {
                LOG(INFO) << "LDAP: the user bind succeeded (dn:" << user_dn_ << ')';
                finishResolved();
            }
            else
            {
                LOG(WARNING) << "LDAP: the user bind failed (result:" << result_code
                             << ldapResultCodeName(result_code) << "diagnostic:" << diagnostic
                             << "dn:" << user_dn_ << ')';
                state_ = State::DONE;
                connection_->close();
                emit sig_denied();
            }
        }
        break;

        case State::BIND_DUMMY:
            // The result says nothing: the bind was against a DN that matches nothing, and it only
            // existed to keep the time spent on the directory comparable (see dummyBind()).
            fail();
            break;

        default:
            break;
    }
}

//--------------------------------------------------------------------------------------------------
void LdapUserResolver::onSearchEntry(const LdapSearchEntry& entry)
{
    entries_.append(entry);
}

//--------------------------------------------------------------------------------------------------
void LdapUserResolver::onSearchFinished(bool success, int result_code, const QString& diagnostic)
{
    switch (state_)
    {
        case State::SEARCH_USER:
        {
            if (!success || entries_.isEmpty())
            {
                // Either the directory failed or the login is not there: the caller may use a local
                // account. When the search worked and found nobody, a bind that matches nothing
                // keeps the time this takes comparable to a wrong password for an existing user.
                if (success)
                {
                    LOG(INFO) << "LDAP: the login was not found in the directory";
                    dummyBind();
                }
                else
                {
                    LOG(WARNING) << "LDAP: the user search failed (result:" << result_code
                                 << ldapResultCodeName(result_code) << "diagnostic:" << diagnostic << ')';
                    fail();
                }
                return;
            }

            const LdapSearchEntry& entry = entries_.first();
            user_dn_ = QString::fromUtf8(entry.object_name);

            readMemberOf(entry);

            LOG(INFO) << "LDAP: the login was found (dn:" << user_dn_ << "groups so far:"
                      << groups_.size() << "entries:" << entries_.size() << ')';

            if (member_range_start_ >= 0)
                startMemberRangeSearch();
            else
                finishMemberOf();
        }
        break;

        case State::SEARCH_USER_RANGE:
        {
            if (!success)
            {
                // The next slice could not be read; the groups that did arrive are still usable.
                LOG(WARNING) << "LDAP: a memberOf range search failed (result:" << result_code
                             << ldapResultCodeName(result_code) << "diagnostic:" << diagnostic << ')';
                member_range_start_ = -1;
                finishMemberOf();
                return;
            }

            if (entries_.isEmpty())
            {
                // The entry did not come back; what has been read is all there is.
                member_range_start_ = -1;
                finishMemberOf();
                return;
            }

            readMemberOf(entries_.first());

            if (member_range_start_ >= 0)
                startMemberRangeSearch();
            else
                finishMemberOf();
        }
        break;

        case State::SEARCH_GROUPS:
        {
            if (!success)
            {
                LOG(WARNING) << "LDAP: the group search failed (result:" << result_code
                             << ldapResultCodeName(result_code) << "diagnostic:" << diagnostic << ')';
                fail();
                return;
            }

            for (const LdapSearchEntry& entry : std::as_const(entries_))
            {
                const QString dn = QString::fromUtf8(entry.object_name);
                if (dn.isEmpty())
                    continue;

                const QString name = groupNameOf(entry, config_.group_attribute);
                if (!name.isEmpty() && !groups_.contains(name, Qt::CaseInsensitive))
                    groups_.append(name);

                // The walk through nested groups goes by DN: a name does not name an entry.
                if (!config_.group_nested && !visited_groups_.contains(dn) &&
                    !expand_queue_.contains(dn))
                {
                    expand_queue_.append(dn);
                }
            }

            LOG(INFO) << "LDAP: groups of the login:" << groups_.size();

            expandGroupsOrFinish();
        }
        break;

        default:
            break;
    }
}

//--------------------------------------------------------------------------------------------------
void LdapUserResolver::onConnectionError()
{
    fail();
}

//--------------------------------------------------------------------------------------------------
void LdapUserResolver::startGroupSearch(const QString& member_dn)
{
    state_ = State::SEARCH_GROUPS;
    entries_.clear();

    const QString membership = QString::fromUtf8(
        ldapGroupMembershipFilter(member_dn.toUtf8(), config_.group_nested));

    QString filter = membership;
    if (!config_.group_filter.isEmpty())
        filter = QStringLiteral("(&") + config_.group_filter + membership + QStringLiteral(")");

    // An empty name attribute would be a malformed request; an empty list asks for every attribute.
    const QList<QByteArray> attributes = config_.group_attribute.isEmpty()
        ? QList<QByteArray>()
        : QList<QByteArray>{ config_.group_attribute.toUtf8() };

    connection_->search(config_.group_base_dn.toUtf8(), LdapScope::Subtree, filter, attributes,
                        LdapConnection::kDefaultPageSize);
}

//--------------------------------------------------------------------------------------------------
void LdapUserResolver::readMemberOf(const LdapSearchEntry& entry)
{
    const QList<QByteArray> member_of =
        ldapAttributeValues(entry.attributes, QByteArrayLiteral("memberOf"));

    for (const QByteArray& dn : member_of)
    {
        // memberOf carries DNs; a mapping names a group the way the directory does.
        const QString name = QString::fromUtf8(ldapNameFromDn(dn));
        if (!name.isEmpty() && !groups_.contains(name, Qt::CaseInsensitive))
            groups_.append(name);
    }

    member_range_start_ = -1;
    ldapRangedAttributeNextStart(entry.attributes, QByteArrayLiteral("memberOf"),
                                 &member_range_start_);
}

//--------------------------------------------------------------------------------------------------
void LdapUserResolver::startMemberRangeSearch()
{
    state_ = State::SEARCH_USER_RANGE;
    entries_.clear();

    if (++member_range_slices_ > kMaxMemberRangeSlices)
    {
        LOG(WARNING) << "LDAP: the directory kept handing out memberOf in ranges; taking what arrived";
        member_range_start_ = -1;
        finishMemberOf();
        return;
    }

    const QByteArray attribute = QByteArrayLiteral("memberOf;range=") +
                                 QByteArray::number(member_range_start_) + QByteArrayLiteral("-*");

    LOG(INFO) << "LDAP: asking for the next slice of memberOf (from" << member_range_start_ << ')';

    // A base-scoped read of the user entry itself returns the next slice of its memberOf.
    connection_->search(user_dn_.toUtf8(), LdapScope::Base, QStringLiteral("(objectClass=*)"),
                        { attribute }, 0);
}

//--------------------------------------------------------------------------------------------------
void LdapUserResolver::finishMemberOf()
{
    if (!config_.group_base_dn.isEmpty())
        startGroupSearch(user_dn_);
    else
        bindUser();
}

//--------------------------------------------------------------------------------------------------
void LdapUserResolver::expandGroupsOrFinish()
{
    // With the AD matching rule in chain one query already returns the transitive closure; without
    // it the direct memberships are walked manually.
    if (!config_.group_nested)
    {
        while (!expand_queue_.isEmpty())
        {
            const QString dn = expand_queue_.takeFirst();
            if (visited_groups_.contains(dn))
                continue;

            visited_groups_.insert(dn);
            startGroupSearch(dn);
            return;
        }
    }

    bindUser();
}

//--------------------------------------------------------------------------------------------------
void LdapUserResolver::bindUser()
{
    LOG(INFO) << "LDAP: binding as the login (dn:" << user_dn_ << "groups:" << groups_.size() << ')';

    state_ = State::BIND_USER;
    connection_->bind(user_dn_.toUtf8(), password_.toUtf8());
}

//--------------------------------------------------------------------------------------------------
void LdapUserResolver::dummyBind()
{
    // The login is not in the directory. Bind anyway, to a DN built from the login that matches
    // nothing, so the work done against the directory, and therefore the time this takes, does not
    // tell an attacker whether the login exists: a wrong password for a real user costs one bind too.
    // The result is discarded and the caller falls back to the local account.
    state_ = State::BIND_DUMMY;

    const QByteArray dn = config_.user_name_attribute.toUtf8() + '=' +
                          ldapEscapeDnValue(login_.toUtf8()) + ',' + config_.base_dn.toUtf8();

    LOG(INFO) << "LDAP: binding against a DN that matches nothing, to keep the timing comparable";

    connection_->bind(dn, password_.toUtf8());
}

//--------------------------------------------------------------------------------------------------
void LdapUserResolver::finishResolved()
{
    state_ = State::DONE;
    connection_->close();

    bool matched = false;
    const quint32 sessions = ldapMapSessions(group_mappings_, user_mappings_, login_, groups_,
                                             config_.default_sessions, config_.deny_if_unmapped,
                                             &matched);
    if (!sessions)
    {
        // The two cases mean different things to the administrator, so they are told apart: nothing
        // names the login at all, or what names it grants no rights.
        if (!matched)
        {
            LOG(INFO) << "LDAP: the login authenticated, but no group or user mapping names" << login_
                      << (config_.deny_if_unmapped
                              ? "; the session is denied (deny_if_unmapped is on)"
                              : "; the rights by default are empty, so the session is denied");
        }
        else
        {
            LOG(INFO) << "LDAP: the login authenticated, but the mapping that names" << login_
                      << "grants it no rights; the session is denied";
        }

        emit sig_denied();
        return;
    }

    LOG(INFO) << "LDAP: resolved" << login_ << "sessions:" << sessions;
    emit sig_resolved(login_, sessions);
}

//--------------------------------------------------------------------------------------------------
void LdapUserResolver::fail()
{
    state_ = State::DONE;

    if (connection_)
        connection_->close();

    LOG(INFO) << "LDAP: the directory could not decide; the caller falls back to the local account";
    emit sig_fallbackToLocal();
}

//--------------------------------------------------------------------------------------------------
void LdapUserResolver::reset()
{
    if (connection_)
    {
        connection_->close();
        connection_->deleteLater();
        connection_ = nullptr;
    }

    state_ = State::IDLE;
    user_dn_.clear();
    groups_.clear();
    visited_groups_.clear();
    expand_queue_.clear();
    entries_.clear();
    member_range_start_ = -1;
    member_range_slices_ = 0;
}
