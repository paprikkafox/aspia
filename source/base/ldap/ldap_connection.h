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

#ifndef BASE_LDAP_LDAP_CONNECTION_H
#define BASE_LDAP_LDAP_CONNECTION_H

#include <QByteArray>
#include <QList>
#include <QObject>
#include <QString>

#include "base/crypto/secure_byte_array.h"
#include "base/ldap/ldap_message.h"
#include "base/time_types.h"

class QSslError;
class QSslSocket;
class QTimer;

//--------------------------------------------------------------------------------------------------
// Asynchronous LDAP v3 client built on Qt's sockets. Every operation is non-blocking; results are
// delivered through signals, so it can be driven from the peer authenticator's event loop.
class LdapConnection final : public QObject
{
    Q_OBJECT

public:
    enum class Security
    {
        Plain,   // No transport encryption.
        Ldaps,   // TLS from the first byte (typically port 636).
        StartTls // Plaintext, then the StartTLS extended request upgrades the socket to TLS.
    };
    Q_ENUM(Security)

    enum class Error
    {
        SOCKET,
        TLS,
        PROTOCOL,
        TIMEOUT
    };
    Q_ENUM(Error)

    struct TlsOptions
    {
        bool verify_peer = true;
        QString ca_certificate;      // The certificate of the CA, PEM encoded; empty keeps the system set.
        QString client_cert_file;    // Optional client certificate (PEM).
        QString client_key_file;     // Optional client private key (PEM).
    };

    explicit LdapConnection(QObject* parent = nullptr);
    ~LdapConnection() final;

    void setSecurity(Security security) { security_ = security; }
    void setTlsOptions(const TlsOptions& options) { tls_options_ = options; }
    void setOperationTimeout(MilliSeconds timeout) { timeout_ = timeout; }

    // Starts the connection. On success sig_connected() is emitted (for StartTls after the TLS
    // upgrade has completed as well).
    void connectToHost(const QString& host, quint16 port);

    // Simple bind. |password| is wiped as soon as the request has been queued.
    void bind(const QByteArray& bind_dn, const SecureByteArray& password);

    // Search. |filter| is the textual RFC 4515 filter; it is encoded internally. When |page_size| is
    // greater than zero the paged results control is used and the pages are fetched transparently.
    void search(const QByteArray& base_dn, LdapScope scope, const QString& filter,
                const QList<QByteArray>& attributes, int page_size = 0);

    // The page size a search is fetched with by default, matching the Active Directory MaxPageSize
    // default. A directory with a lower cap still serves its own page size, and one without paged
    // results ignores the control and answers in a single response.
    static constexpr int kDefaultPageSize = 1000;

    void close();

signals:
    void sig_connected();
    void sig_bound(bool success, int result_code, const QString& diagnostic);
    void sig_searchEntry(const LdapSearchEntry& entry);
    void sig_searchFinished(bool success, int result_code, const QString& diagnostic);
    void sig_errorOccurred(LdapConnection::Error error, const QString& text);

private:
    void onConnected();
    void onEncrypted();
    void onReadyRead();
    void onSocketError();
    void onSslErrors(const QList<QSslError>& errors);
    void onTimeout();

    void applyTlsConfiguration();
    void send(const QByteArray& message);
    void startTimer();
    void stopTimer();
    void fail(Error error, const QString& text);
    void handleMessage(const QByteArray& message);
    void sendSearchPage();

    QSslSocket* socket_;
    QTimer* timer_;

    Security security_ = Security::StartTls;
    TlsOptions tls_options_;
    MilliSeconds timeout_ { 10000 };

    bool starttls_pending_ = false;

    QByteArray buffer_;
    int next_message_id_ = 1;

    enum class Operation { NONE, BIND, SEARCH };
    Operation operation_ = Operation::NONE;
    int pending_message_id_ = 0;

    // Search state, kept so the next page can be requested.
    QByteArray search_base_dn_;
    LdapScope search_scope_ = LdapScope::Subtree;
    QByteArray search_filter_;
    QList<QByteArray> search_attributes_;
    int search_page_size_ = 0;
    int search_page_count_ = 0;
    QByteArray search_cookie_;

    Q_DISABLE_COPY_MOVE(LdapConnection)
};

#endif // BASE_LDAP_LDAP_CONNECTION_H
