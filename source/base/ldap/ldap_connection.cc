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

#include "base/ldap/ldap_connection.h"

#include <QFile>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslError>
#include <QSslKey>
#include <QSslSocket>
#include <QTimer>

#include "base/ldap/ldap_filter.h"

namespace {

// The number of pages one search may fetch; a directory that never ends its paging is cut off here.
// At the default page size it is far beyond any real directory.
constexpr int kMaxSearchPages = 10000;

} // namespace

//--------------------------------------------------------------------------------------------------
LdapConnection::LdapConnection(QObject* parent)
    : QObject(parent),
      socket_(new QSslSocket(this)),
      timer_(new QTimer(this))
{
    timer_->setSingleShot(true);
    connect(timer_, &QTimer::timeout, this, &LdapConnection::onTimeout);

    connect(socket_, &QAbstractSocket::connected, this, &LdapConnection::onConnected);
    connect(socket_, &QSslSocket::encrypted, this, &LdapConnection::onEncrypted);
    connect(socket_, &QAbstractSocket::readyRead, this, &LdapConnection::onReadyRead);
    connect(socket_, &QAbstractSocket::errorOccurred, this,
            [this](QAbstractSocket::SocketError) { onSocketError(); });
    connect(socket_, &QSslSocket::sslErrors, this,
            [this](const QList<QSslError>& errors) { onSslErrors(errors); });
}

//--------------------------------------------------------------------------------------------------
LdapConnection::~LdapConnection() = default;

//--------------------------------------------------------------------------------------------------
void LdapConnection::applyTlsConfiguration()
{
    QSslConfiguration config = QSslConfiguration::defaultConfiguration();

    config.setPeerVerifyMode(tls_options_.verify_peer ? QSslSocket::VerifyPeer
                                                      : QSslSocket::VerifyNone);

    if (!tls_options_.ca_certificate.isEmpty())
    {
        // The certificate is held as the text of the PEM file, so it travels with the settings and
        // the exported configuration instead of pointing at a path that exists on one machine.
        const QList<QSslCertificate> ca_certificates =
            QSslCertificate::fromData(tls_options_.ca_certificate.toUtf8(), QSsl::Pem);
        if (!ca_certificates.isEmpty())
            config.setCaCertificates(ca_certificates);
    }

    if (!tls_options_.client_cert_file.isEmpty())
    {
        const QList<QSslCertificate> certificates =
            QSslCertificate::fromPath(tls_options_.client_cert_file);
        if (!certificates.isEmpty())
            config.setLocalCertificateChain(certificates);
    }

    if (!tls_options_.client_key_file.isEmpty())
    {
        QFile key_file(tls_options_.client_key_file);
        if (key_file.open(QIODevice::ReadOnly))
        {
            QSslKey key(&key_file, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
            if (key.isNull())
            {
                key_file.seek(0);
                key = QSslKey(&key_file, QSsl::Ec, QSsl::Pem, QSsl::PrivateKey);
            }

            if (!key.isNull())
                config.setPrivateKey(key);
        }
    }

    socket_->setSslConfiguration(config);
}

//--------------------------------------------------------------------------------------------------
void LdapConnection::connectToHost(const QString& host, quint16 port)
{
    buffer_.clear();
    operation_ = Operation::NONE;
    starttls_pending_ = false;

    applyTlsConfiguration();

    if (security_ == Security::Ldaps)
        socket_->connectToHostEncrypted(host, port);
    else
        socket_->connectToHost(host, port);

    startTimer();
}

//--------------------------------------------------------------------------------------------------
void LdapConnection::onConnected()
{
    if (security_ == Security::StartTls)
    {
        starttls_pending_ = true;
        send(ldapBuildStartTlsRequest(next_message_id_++));
        startTimer();
        return;
    }

    if (security_ == Security::Plain)
    {
        stopTimer();
        emit sig_connected();
    }

    // Ldaps waits for onEncrypted().
}

//--------------------------------------------------------------------------------------------------
void LdapConnection::onEncrypted()
{
    stopTimer();
    emit sig_connected();
}

//--------------------------------------------------------------------------------------------------
void LdapConnection::onReadyRead()
{
    buffer_.append(socket_->readAll());

    for (;;)
    {
        const qsizetype size = ldapMessageSize(buffer_);
        if (size == 0)
            break;

        if (size < 0)
        {
            fail(Error::PROTOCOL, QStringLiteral("Malformed LDAP message"));
            return;
        }

        const QByteArray message = buffer_.left(size);
        buffer_.remove(0, size);

        handleMessage(message);
    }
}

//--------------------------------------------------------------------------------------------------
void LdapConnection::onSocketError()
{
    fail(Error::SOCKET, socket_->errorString());
}

//--------------------------------------------------------------------------------------------------
void LdapConnection::onSslErrors(const QList<QSslError>& errors)
{
    if (!tls_options_.verify_peer)
    {
        socket_->ignoreSslErrors();
        return;
    }

    QString text;
    for (const QSslError& error : errors)
    {
        if (!text.isEmpty())
            text += QStringLiteral("; ");
        text += error.errorString();
    }

    fail(Error::TLS, text);
}

//--------------------------------------------------------------------------------------------------
void LdapConnection::onTimeout()
{
    fail(Error::TIMEOUT, QStringLiteral("LDAP operation timed out"));
}

//--------------------------------------------------------------------------------------------------
void LdapConnection::bind(const QByteArray& bind_dn, const SecureByteArray& password)
{
    operation_ = Operation::BIND;
    pending_message_id_ = next_message_id_++;

    // An empty bind DN asks for an anonymous bind (RFC 4513 section 5.1.1), which must carry an empty
    // password as well. A password left over from a service account whose DN was cleared would turn
    // the request into an "unauthenticated bind", which a server is required to refuse; it is dropped
    // together with the DN.
    QByteArray raw_password = bind_dn.isEmpty() ? QByteArray() : password.toByteArray();

    QByteArray message = ldapBuildBindRequest(pending_message_id_, bind_dn, raw_password);
    send(message);

    // The request buffers held a copy of the password; wipe them before releasing.
    message.fill('\0');
    raw_password.fill('\0');

    startTimer();
}

//--------------------------------------------------------------------------------------------------
void LdapConnection::search(const QByteArray& base_dn, LdapScope scope, const QString& filter,
                            const QList<QByteArray>& attributes, int page_size)
{
    if (!ldapEncodeFilter(filter, &search_filter_))
    {
        fail(Error::PROTOCOL, QStringLiteral("Invalid LDAP filter"));
        return;
    }

    search_base_dn_ = base_dn;
    search_scope_ = scope;
    search_attributes_ = attributes;
    search_page_size_ = page_size;
    search_page_count_ = 0;
    search_cookie_.clear();

    sendSearchPage();
}

//--------------------------------------------------------------------------------------------------
void LdapConnection::sendSearchPage()
{
    if (++search_page_count_ > kMaxSearchPages)
    {
        fail(Error::PROTOCOL, QStringLiteral("The directory returned too many pages"));
        return;
    }

    operation_ = Operation::SEARCH;
    pending_message_id_ = next_message_id_++;

    QByteArray message;
    if (search_page_size_ > 0)
    {
        message = ldapBuildSearchRequestPaged(pending_message_id_, search_base_dn_, search_scope_,
                                              search_filter_, search_attributes_, search_page_size_,
                                              search_cookie_);
    }
    else
    {
        message = ldapBuildSearchRequest(pending_message_id_, search_base_dn_, search_scope_,
                                         search_filter_, search_attributes_);
    }

    send(message);
    startTimer();
}

//--------------------------------------------------------------------------------------------------
void LdapConnection::close()
{
    stopTimer();
    buffer_.clear();
    operation_ = Operation::NONE;

    if (socket_->state() != QAbstractSocket::UnconnectedState)
        socket_->disconnectFromHost();
}

//--------------------------------------------------------------------------------------------------
void LdapConnection::send(const QByteArray& message)
{
    socket_->write(message);
}

//--------------------------------------------------------------------------------------------------
void LdapConnection::startTimer()
{
    timer_->start(timeout_);
}

//--------------------------------------------------------------------------------------------------
void LdapConnection::stopTimer()
{
    timer_->stop();
}

//--------------------------------------------------------------------------------------------------
void LdapConnection::fail(Error error, const QString& text)
{
    stopTimer();
    buffer_.clear();
    operation_ = Operation::NONE;

    if (socket_->state() != QAbstractSocket::UnconnectedState)
        socket_->disconnectFromHost();

    emit sig_errorOccurred(error, text);
}

//--------------------------------------------------------------------------------------------------
void LdapConnection::handleMessage(const QByteArray& message)
{
    LdapResponse response;
    if (!ldapParseResponse(message, &response))
    {
        fail(Error::PROTOCOL, QStringLiteral("Malformed LDAP response"));
        return;
    }

    if (starttls_pending_)
    {
        starttls_pending_ = false;

        if (response.op == LdapOp::ExtendedResponse && response.result.code == 0)
        {
            socket_->startClientEncryption();
            // sig_connected() follows from onEncrypted().
        }
        else
        {
            fail(Error::TLS, QStringLiteral("StartTLS was refused by the server"));
        }
        return;
    }

    if (response.message_id != pending_message_id_)
        return;

    switch (response.op)
    {
        case LdapOp::BindResponse:
            stopTimer();
            emit sig_bound(response.result.code == 0, response.result.code,
                           QString::fromUtf8(response.result.diagnostic));
            break;

        case LdapOp::SearchResultEntry:
            emit sig_searchEntry(response.entry);
            break;

        case LdapOp::SearchResultReference:
            // Referrals are not followed.
            break;

        case LdapOp::SearchResultDone:
        {
            const bool more_pages = search_page_size_ > 0 && response.has_paged_cookie &&
                                    !response.paged_cookie.isEmpty();

            // A page that failed for any reason but the size cap ends the search; the next page is
            // not requested after a refusal.
            const bool page_failed = response.result.code != 0 && response.result.code != 4;

            // A cookie that does not move on would page forever; a directory that repeats one is
            // broken, and the search is ended with its last result instead of paging on.
            const bool stuck = more_pages && response.paged_cookie == search_cookie_;

            if (more_pages && !page_failed && !stuck)
            {
                search_cookie_ = response.paged_cookie;
                sendSearchPage();
            }
            else
            {
                stopTimer();

                if (stuck)
                {
                    emit sig_searchFinished(false, response.result.code,
                                            QStringLiteral("The directory repeated a page"));
                }
                else
                {
                    emit sig_searchFinished(response.result.code == 0, response.result.code,
                                            QString::fromUtf8(response.result.diagnostic));
                }
            }
        }
        break;

        case LdapOp::ExtendedResponse:
            stopTimer();
            emit sig_searchFinished(response.result.code == 0, response.result.code,
                                    QString::fromUtf8(response.result.diagnostic));
            break;

        default:
            break;
    }
}
