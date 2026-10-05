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

#ifndef HOST_LDAP_USER_RESOLVER_H
#define HOST_LDAP_USER_RESOLVER_H

#include <QByteArray>
#include <QObject>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QVector>

#include "base/crypto/secure_string.h"
#include "base/ldap/ldap_message.h"
#include "host/database.h"

class LdapConnection;

// Maps a resolved set of group names and the login to the permission bitmask: the rights of every
// matching source are combined with a bitwise OR, so the highest privilege wins.
// When nothing matches, |default_sessions| is used, or the result is zero when |deny_if_unmapped|.
// |*matched|, when it is given, says whether any group or the user entry named the login at all, so
// a caller can tell "nothing names this login" from "what names it grants no rights".
quint32 ldapMapSessions(const QVector<Database::LdapMapping>& group_mappings,
                        const QVector<Database::LdapMapping>& user_mappings,
                        const QString& login, const QStringList& group_dns,
                        quint32 default_sessions, bool deny_if_unmapped, bool* matched = nullptr);

//--------------------------------------------------------------------------------------------------
// Resolves an LDAP login to the host permission bitmask, asynchronously and without blocking the
// event loop. The result is one of:
//   sig_resolved    - the user authenticated through LDAP and got |sessions|;
//   sig_denied      - LDAP is authoritative and refused (bad password or no rights);
//   sig_fallbackToLocal - LDAP could not decide (unreachable, or the user is not in the directory),
//                     so the caller should validate the credentials against a local account.
//
// A successful user bind is what proves the password: the resolver binds as the matched user DN only
// after the search and group resolution have completed, so the read access used for the search is
// the service account's.
//
// The resolver and the connection it makes have to live on a thread that uses the standard Qt event
// dispatcher: a Qt socket is only told that it has become ready by that dispatcher, while the server
// threads run on the asio dispatcher. HostLdapCredentialResolver moves the resolver onto such a
// thread; a caller that keeps the resolver itself must do the same.
class LdapUserResolver : public QObject
{
    Q_OBJECT

public:
    explicit LdapUserResolver(QObject* parent = nullptr);
    ~LdapUserResolver() final;

    void setConfig(const Database::LdapConfig& config);
    void setMappings(const QVector<Database::LdapMapping>& groups,
                     const QVector<Database::LdapMapping>& users);

    void resolve(const QString& login, const SecureString& password);
    void cancel();

signals:
    void sig_resolved(const QString& user_name, quint32 sessions);
    void sig_denied();
    void sig_fallbackToLocal();

private:
    enum class State
    {
        IDLE,
        CONNECTING,
        BIND_SERVICE,
        SEARCH_USER,
        SEARCH_USER_RANGE,
        SEARCH_GROUPS,
        BIND_USER,
        BIND_DUMMY,
        DONE
    };

    void onConnected();
    void onBound(bool success, int result_code, const QString& diagnostic);
    void onSearchEntry(const LdapSearchEntry& entry);
    void onSearchFinished(bool success, int result_code, const QString& diagnostic);
    void onConnectionError();

    void startGroupSearch(const QString& member_dn);
    void expandGroupsOrFinish();
    void bindUser();
    void dummyBind();
    void finishResolved();
    void fail();

    // The groups memberOf names are read in full: Active Directory hands the attribute out in ranges
    // when a user is in more groups than fit one response, and each slice after the first is asked
    // for by name.
    void readMemberOf(const LdapSearchEntry& entry);
    void startMemberRangeSearch();
    void finishMemberOf();

    void reset();

    LdapConnection* connection_ = nullptr;
    State state_ = State::IDLE;

    Database::LdapConfig config_;
    QVector<Database::LdapMapping> group_mappings_;
    QVector<Database::LdapMapping> user_mappings_;

    QString login_;
    SecureString password_;

    QString user_dn_;
    QStringList groups_;
    QSet<QString> visited_groups_;
    QStringList expand_queue_;
    QVector<LdapSearchEntry> entries_;

    // The index the next memberOf range starts at, or -1 when the whole attribute has been read.
    int member_range_start_ = -1;
    int member_range_slices_ = 0;

    Q_DISABLE_COPY_MOVE(LdapUserResolver)
};

#endif // HOST_LDAP_USER_RESOLVER_H
