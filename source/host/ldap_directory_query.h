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

#ifndef HOST_LDAP_DIRECTORY_QUERY_H
#define HOST_LDAP_DIRECTORY_QUERY_H

#include <QObject>
#include <QString>
#include <QVector>

#include "base/crypto/secure_string.h"
#include "host/database.h"

class LdapConnection;
struct LdapSearchEntry;

//--------------------------------------------------------------------------------------------------
// Runs one read-only operation against the directory on behalf of the settings UI, asynchronously so
// the dialog stays responsive while the directory answers. Two uses: listing the users or the groups
// a picker offers, and checking a login by binding with it (the same service bind, search and user
// bind the authenticator does, but reported to the operator instead of deciding access).
//
// The connection is short lived and belongs to this object; cancel() (or destroying the object)
// drops it. Nothing is cached: the pickers are opened rarely and stale lists are worse than a wait.
class LdapDirectoryQuery : public QObject
{
    Q_OBJECT

public:
    // One entry a picker lists. Fields that do not apply to the kind stay empty.
    struct Entry
    {
        QString name;        // The display name (users) or the group name (groups).
        QString login;       // The login attribute ("sAMAccountName", ...). Users only.
        QString description; // The description. Groups only.
        QString dn;          // The distinguished name.
    };

    enum class Kind
    {
        USER,
        GROUP
    };

    // Reported by sig_loginChecked when the login is not in the directory. LDAP result code 0 means
    // success, so a negative value keeps "not found" apart from every real result code.
    static constexpr int kLoginNotFound = -1;

    explicit LdapDirectoryQuery(QObject* parent = nullptr);
    ~LdapDirectoryQuery() final;

    // Lists the users, or the groups, the settings point at.
    void search(const Database::LdapConfig& config, Kind kind);

    // Checks |login| by finding it and binding as it with |password|. The service account (or an
    // anonymous bind when no bind DN is set) is used for the search.
    void checkLogin(const Database::LdapConfig& config, const QString& login,
                    const SecureString& password);

    void cancel();

signals:
    void sig_entriesFound(const QVector<LdapDirectoryQuery::Entry>& entries);

    // The bind check finished. |result_code| is the LDAP code, kLoginNotFound when there was no such
    // login, and 0 with |success| true when the bind worked.
    void sig_loginChecked(bool success, int result_code, const QString& diagnostic,
                          const QString& user_dn);

    // The operation could not be completed at all (no connection, a malformed answer, a refusal).
    void sig_failed(const QString& message);

private:
    enum class State
    {
        IDLE,
        CONNECTING,
        BIND_SERVICE,
        SEARCH_LIST,
        SEARCH_LOGIN,
        BIND_USER,
        DONE
    };

    enum class Operation
    {
        NONE,
        LIST,
        CHECK
    };

    void start(const Database::LdapConfig& config);
    void onConnected();
    void onBound(bool success, int result_code, const QString& diagnostic);
    void onSearchEntry(const LdapSearchEntry& entry);
    void onSearchFinished(bool success, int result_code, const QString& diagnostic);

    void bindService();
    void startListSearch();
    void startLoginSearch();
    void bindUser();
    void finishList();
    void finishCheck(bool success, int result_code, const QString& diagnostic);
    void fail(const QString& message);
    void reset();

    LdapConnection* connection_ = nullptr;
    State state_ = State::IDLE;
    Operation operation_ = Operation::NONE;

    Database::LdapConfig config_;
    Kind kind_ = Kind::USER;

    QString login_;
    SecureString password_;
    QString user_dn_;
    QVector<Entry> entries_;

    Q_DISABLE_COPY_MOVE(LdapDirectoryQuery)
};

#endif // HOST_LDAP_DIRECTORY_QUERY_H
