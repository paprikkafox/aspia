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

#include <gtest/gtest.h>

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QHostAddress>
#include <QTcpServer>
#include <QTcpSocket>

#include <functional>

#include "base/crypto/secure_byte_array.h"
#include "base/ldap/ldap_ber.h"
#include "base/ldap/ldap_message.h"

namespace {

//--------------------------------------------------------------------------------------------------
bool waitFor(const std::function<bool()>& predicate, int timeout_ms = 3000)
{
    QElapsedTimer timer;
    timer.start();

    while (!predicate() && timer.elapsed() < timeout_ms)
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);

    return predicate();
}

//--------------------------------------------------------------------------------------------------
// Reads the message id and the protocol-op tag of an LDAP request (requests do not use the response
// parser, which only understands the ops a server sends back).
bool readRequestInfo(const QByteArray& message, int* message_id, quint8* op)
{
    BerDecoder decoder(message);
    quint8 tag = 0;

    if (!decoder.readElement(&tag) || tag != static_cast<quint8>(BerTag::Sequence))
        return false;

    BerDecoder body = decoder.nested();

    if (!body.readElement(&tag) || tag != static_cast<quint8>(BerTag::Integer))
        return false;

    qint64 id = 0;
    if (!body.toInteger(&id))
        return false;
    *message_id = static_cast<int>(id);

    if (!body.readElement(&tag))
        return false;
    *op = tag;

    return true;
}

//--------------------------------------------------------------------------------------------------
// Reads the bind DN and the simple-authentication password out of a bind request, so a test can see
// what the client put on the wire (the request parser only understands the ops a server sends back).
bool readBind(const QByteArray& message, QByteArray* name, QByteArray* password)
{
    BerDecoder decoder(message);
    quint8 tag = 0;

    if (!decoder.readElement(&tag) || tag != static_cast<quint8>(BerTag::Sequence))
        return false;

    BerDecoder body = decoder.nested();

    if (!body.readElement(&tag) || tag != static_cast<quint8>(BerTag::Integer)) // message id
        return false;

    if (!body.readElement(&tag) || tag != static_cast<quint8>(LdapOp::BindRequest))
        return false;

    BerDecoder bind = body.nested();

    if (!bind.readElement(&tag) || tag != static_cast<quint8>(BerTag::Integer)) // version
        return false;

    if (!bind.readElement(&tag) || tag != static_cast<quint8>(BerTag::OctetString)) // name
        return false;
    if (!bind.toOctetString(name))
        return false;

    if (!bind.readElement(&tag) || tag != (static_cast<quint8>(BerClass::Context) | 0)) // password
        return false;

    return bind.toOctetString(password);
}

//--------------------------------------------------------------------------------------------------
QByteArray makeBindResponse(int message_id, int code)
{
    BerEncoder result;
    result.writeEnumerated(static_cast<quint32>(code));
    result.writeOctetString(QByteArray());
    result.writeOctetString(QByteArray());

    BerEncoder op;
    op.writeElement(static_cast<quint8>(LdapOp::BindResponse), result.data());

    BerEncoder body;
    body.writeInteger(message_id);
    body.writeRaw(op.data());

    BerEncoder message;
    message.writeSequence(body.data());
    return message.data();
}

//--------------------------------------------------------------------------------------------------
QByteArray makeSearchEntry(int message_id, const QByteArray& object_name, const QByteArray& attribute,
                           const QByteArray& value)
{
    BerEncoder values;
    values.writeOctetString(value);

    BerEncoder set;
    set.writeSet(values.data());

    BerEncoder partial;
    partial.writeOctetString(attribute);
    partial.writeRaw(set.data());

    BerEncoder partial_attribute;
    partial_attribute.writeSequence(partial.data());

    BerEncoder attributes;
    attributes.writeSequence(partial_attribute.data());

    BerEncoder entry;
    entry.writeOctetString(object_name);
    entry.writeRaw(attributes.data());

    BerEncoder op;
    op.writeElement(static_cast<quint8>(LdapOp::SearchResultEntry), entry.data());

    BerEncoder body;
    body.writeInteger(message_id);
    body.writeRaw(op.data());

    BerEncoder message;
    message.writeSequence(body.data());
    return message.data();
}

//--------------------------------------------------------------------------------------------------
QByteArray makeSearchDone(int message_id, int code)
{
    BerEncoder result;
    result.writeEnumerated(static_cast<quint32>(code));
    result.writeOctetString(QByteArray());
    result.writeOctetString(QByteArray());

    BerEncoder op;
    op.writeElement(static_cast<quint8>(LdapOp::SearchResultDone), result.data());

    BerEncoder body;
    body.writeInteger(message_id);
    body.writeRaw(op.data());

    BerEncoder message;
    message.writeSequence(body.data());
    return message.data();
}

//--------------------------------------------------------------------------------------------------
QByteArray makeSearchDonePaged(int message_id, int code, const QByteArray& cookie)
{
    BerEncoder result;
    result.writeEnumerated(static_cast<quint32>(code));
    result.writeOctetString(QByteArray());
    result.writeOctetString(QByteArray());

    BerEncoder op;
    op.writeElement(static_cast<quint8>(LdapOp::SearchResultDone), result.data());

    BerEncoder paged;
    paged.writeInteger(0);
    paged.writeOctetString(cookie);

    BerEncoder paged_value;
    paged_value.writeSequence(paged.data());

    BerEncoder control_body;
    control_body.writeOctetString(QByteArray(kLdapPagedResultsOid));
    control_body.writeBoolean(false);
    control_body.writeOctetString(paged_value.data());

    BerEncoder control;
    control.writeSequence(control_body.data());

    BerEncoder controls;
    controls.writeContext(0, true, control.data());

    BerEncoder body;
    body.writeInteger(message_id);
    body.writeRaw(op.data());
    body.writeRaw(controls.data());

    BerEncoder message;
    message.writeSequence(body.data());
    return message.data();
}

//--------------------------------------------------------------------------------------------------
// A minimal in-process LDAP server: it answers a bind with success, a search with one entry followed
// by a done, and closes on unbind.
class FakeLdapServer
{
public:
    bool listen()
    {
        QObject::connect(&server_, &QTcpServer::newConnection, &server_, [this]()
        {
            QTcpSocket* socket = server_.nextPendingConnection();
            socket->setParent(&server_);

            QObject::connect(socket, &QTcpSocket::readyRead, socket, [this, socket]()
            {
                buffers_[socket].append(socket->readAll());

                for (;;)
                {
                    const qsizetype size = ldapMessageSize(buffers_[socket]);
                    if (size <= 0)
                        break;

                    const QByteArray message = buffers_[socket].left(size);
                    buffers_[socket].remove(0, size);

                    respond(socket, message);
                }
            });
        });

        return server_.listen(QHostAddress::LocalHost, 0);
    }

    quint16 port() const { return server_.serverPort(); }

    // The cookie put on the done of the |index|-th search (0-based), consulted only for a search that
    // carried the paged results control. An empty cookie ends the search; when unset every search is
    // answered with a single page and no control.
    std::function<QByteArray(int)> cookie_for_search;

    // The result code of the |index|-th search; zero (success) when unset.
    std::function<int(int)> code_for_search;

    // The bind request exactly as it was received, so a test can inspect the credentials the client
    // put on the wire.
    QByteArray last_bind_request;

private:
    void respond(QTcpSocket* socket, const QByteArray& request)
    {
        int message_id = 0;
        quint8 op = 0;
        if (!readRequestInfo(request, &message_id, &op))
            return;

        switch (static_cast<LdapOp>(op))
        {
            case LdapOp::BindRequest:
                last_bind_request = request;
                socket->write(makeBindResponse(message_id, 0));
                break;

            case LdapOp::SearchRequest:
            {
                const int index = search_count_++;
                const int code = code_for_search ? code_for_search(index) : 0;
                const bool paged = request.contains(kLdapPagedResultsOid);
                const QByteArray cookie = (paged && cookie_for_search)
                    ? cookie_for_search(index)
                    : QByteArray();

                socket->write(makeSearchEntry(message_id,
                                              QByteArrayLiteral("uid=page") + QByteArray::number(index),
                                              QByteArrayLiteral("cn"), QByteArrayLiteral("Name")));

                if (paged && cookie_for_search)
                    socket->write(makeSearchDonePaged(message_id, code, cookie));
                else
                    socket->write(makeSearchDone(message_id, code));
                break;
            }

            case LdapOp::UnbindRequest:
                socket->disconnectFromHost();
                break;

            default:
                break;
        }
    }

    QTcpServer server_;
    QHash<QTcpSocket*, QByteArray> buffers_;
    int search_count_ = 0;
};

} // namespace

//--------------------------------------------------------------------------------------------------
TEST(LdapConnectionTest, BindAndSearch)
{
    FakeLdapServer server;
    ASSERT_TRUE(server.listen());

    LdapConnection connection;
    connection.setSecurity(LdapConnection::Security::Plain);
    connection.setOperationTimeout(MilliSeconds(3000));

    bool connected = false;
    bool bound_ok = false;
    int entries = 0;
    bool search_done = false;
    int errors = 0;

    QObject::connect(&connection, &LdapConnection::sig_connected, &connection,
                     [&connected]() { connected = true; });
    QObject::connect(&connection, &LdapConnection::sig_bound, &connection,
                     [&bound_ok](bool success, int, const QString&) { bound_ok = success; });
    QObject::connect(&connection, &LdapConnection::sig_searchEntry, &connection,
                     [&entries](const LdapSearchEntry&) { ++entries; });
    QObject::connect(&connection, &LdapConnection::sig_searchFinished, &connection,
                     [&search_done](bool success, int, const QString&) { search_done = success; });
    QObject::connect(&connection, &LdapConnection::sig_errorOccurred, &connection,
                     [&errors](LdapConnection::Error, const QString&) { ++errors; });

    connection.connectToHost(QStringLiteral("127.0.0.1"), server.port());
    ASSERT_TRUE(waitFor([&connected]() { return connected; })) << "did not connect";

    connection.bind(QByteArrayLiteral("cn=admin,dc=x"), SecureByteArray(QByteArrayLiteral("secret")));
    ASSERT_TRUE(waitFor([&bound_ok]() { return bound_ok; })) << "bind did not succeed";

    connection.search(QByteArrayLiteral("dc=x"), LdapScope::Subtree,
                      QStringLiteral("(&(objectClass=person)(uid=jdoe))"),
                      { QByteArrayLiteral("cn") }, 0);
    ASSERT_TRUE(waitFor([&search_done]() { return search_done; })) << "search did not finish";

    EXPECT_EQ(entries, 1);
    EXPECT_EQ(errors, 0);
}

//--------------------------------------------------------------------------------------------------
TEST(LdapConnectionTest, RejectsInvalidFilter)
{
    LdapConnection connection;

    bool failed = false;
    QObject::connect(&connection, &LdapConnection::sig_errorOccurred, &connection,
                     [&failed](LdapConnection::Error error, const QString&)
    {
        if (error == LdapConnection::Error::PROTOCOL)
            failed = true;
    });

    // No connection is needed: the filter is validated before anything is sent.
    connection.search(QByteArrayLiteral("dc=x"), LdapScope::Subtree, QStringLiteral("not a filter"),
                      {}, 0);

    EXPECT_TRUE(failed);
}

//--------------------------------------------------------------------------------------------------
TEST(LdapConnectionTest, PagedSearchFetchesEveryPage)
{
    FakeLdapServer server;
    server.cookie_for_search = [](int index) -> QByteArray
    {
        // Three pages: the first two say there is more, the third ends the search.
        return index < 2 ? QByteArray::number(index) : QByteArray();
    };
    ASSERT_TRUE(server.listen());

    LdapConnection connection;
    connection.setSecurity(LdapConnection::Security::Plain);
    connection.setOperationTimeout(MilliSeconds(3000));

    bool connected = false;
    int entries = 0;
    bool finished = false;
    bool finished_success = false;

    QObject::connect(&connection, &LdapConnection::sig_connected, &connection,
                     [&connected]() { connected = true; });
    QObject::connect(&connection, &LdapConnection::sig_searchEntry, &connection,
                     [&entries](const LdapSearchEntry&) { ++entries; });
    QObject::connect(&connection, &LdapConnection::sig_searchFinished, &connection,
                     [&finished, &finished_success](bool success, int, const QString&)
    {
        finished = true;
        finished_success = success;
    });

    connection.connectToHost(QStringLiteral("127.0.0.1"), server.port());
    ASSERT_TRUE(waitFor([&connected]() { return connected; })) << "did not connect";

    connection.search(QByteArrayLiteral("dc=x"), LdapScope::Subtree, QStringLiteral("(cn=*)"),
                      { QByteArrayLiteral("cn") }, LdapConnection::kDefaultPageSize);
    ASSERT_TRUE(waitFor([&finished]() { return finished; })) << "the search did not finish";

    EXPECT_TRUE(finished_success);
    // One entry per page, and the pages after the first only came because the control was sent.
    EXPECT_EQ(entries, 3);
}

//--------------------------------------------------------------------------------------------------
TEST(LdapConnectionTest, PagedSearchStopsOnRepeatedCookie)
{
    FakeLdapServer server;
    server.cookie_for_search = [](int) -> QByteArray { return QByteArrayLiteral("stuck"); };
    ASSERT_TRUE(server.listen());

    LdapConnection connection;
    connection.setSecurity(LdapConnection::Security::Plain);
    connection.setOperationTimeout(MilliSeconds(3000));

    bool connected = false;
    int entries = 0;
    bool finished = false;
    bool finished_success = true;

    QObject::connect(&connection, &LdapConnection::sig_connected, &connection,
                     [&connected]() { connected = true; });
    QObject::connect(&connection, &LdapConnection::sig_searchEntry, &connection,
                     [&entries](const LdapSearchEntry&) { ++entries; });
    QObject::connect(&connection, &LdapConnection::sig_searchFinished, &connection,
                     [&finished, &finished_success](bool success, int, const QString&)
    {
        finished = true;
        finished_success = success;
    });

    connection.connectToHost(QStringLiteral("127.0.0.1"), server.port());
    ASSERT_TRUE(waitFor([&connected]() { return connected; })) << "did not connect";

    connection.search(QByteArrayLiteral("dc=x"), LdapScope::Subtree, QStringLiteral("(cn=*)"),
                      { QByteArrayLiteral("cn") }, LdapConnection::kDefaultPageSize);
    ASSERT_TRUE(waitFor([&finished]() { return finished; })) << "the search did not stop";

    // A cookie that does not move on ends the search instead of paging forever.
    EXPECT_FALSE(finished_success);
    EXPECT_EQ(entries, 2);
}

//--------------------------------------------------------------------------------------------------
TEST(LdapConnectionTest, PagedSearchStopsOnFailedPage)
{
    FakeLdapServer server;
    server.cookie_for_search = [](int) -> QByteArray { return QByteArrayLiteral("more"); };
    server.code_for_search = [](int) { return 50; }; // insufficientAccessRights
    ASSERT_TRUE(server.listen());

    LdapConnection connection;
    connection.setSecurity(LdapConnection::Security::Plain);
    connection.setOperationTimeout(MilliSeconds(3000));

    bool connected = false;
    int entries = 0;
    bool finished = false;
    bool finished_success = true;
    int finished_code = 0;

    QObject::connect(&connection, &LdapConnection::sig_connected, &connection,
                     [&connected]() { connected = true; });
    QObject::connect(&connection, &LdapConnection::sig_searchEntry, &connection,
                     [&entries](const LdapSearchEntry&) { ++entries; });
    QObject::connect(&connection, &LdapConnection::sig_searchFinished, &connection,
                     [&finished, &finished_success, &finished_code](bool success, int code, const QString&)
    {
        finished = true;
        finished_success = success;
        finished_code = code;
    });

    connection.connectToHost(QStringLiteral("127.0.0.1"), server.port());
    ASSERT_TRUE(waitFor([&connected]() { return connected; })) << "did not connect";

    connection.search(QByteArrayLiteral("dc=x"), LdapScope::Subtree, QStringLiteral("(cn=*)"),
                      { QByteArrayLiteral("cn") }, LdapConnection::kDefaultPageSize);
    ASSERT_TRUE(waitFor([&finished]() { return finished; })) << "the search did not finish";

    // A page that failed for a reason other than the size cap is not paged past.
    EXPECT_FALSE(finished_success);
    EXPECT_EQ(finished_code, 50);
    EXPECT_EQ(entries, 1);
}

//--------------------------------------------------------------------------------------------------
// An empty bind DN is an anonymous bind and must carry an empty password (RFC 4513 section 5.1.1).
// A password left over from a cleared account would make it an "unauthenticated bind", which a
// server is required to refuse.
TEST(LdapConnectionTest, AnonymousBindCarriesNoPassword)
{
    FakeLdapServer server;
    ASSERT_TRUE(server.listen());

    LdapConnection connection;
    connection.setSecurity(LdapConnection::Security::Plain);
    connection.setOperationTimeout(MilliSeconds(3000));

    bool connected = false;
    bool bound = false;

    QObject::connect(&connection, &LdapConnection::sig_connected, &connection,
                     [&connected]() { connected = true; });
    QObject::connect(&connection, &LdapConnection::sig_bound, &connection,
                     [&bound](bool, int, const QString&) { bound = true; });

    connection.connectToHost(QStringLiteral("127.0.0.1"), server.port());
    ASSERT_TRUE(waitFor([&connected]() { return connected; })) << "did not connect";

    // An empty DN with a password set still has to go out as an anonymous bind.
    bound = false;
    connection.bind(QByteArray(), SecureByteArray(QByteArrayLiteral("secret")));
    ASSERT_TRUE(waitFor([&bound]() { return bound; })) << "the anonymous bind did not finish";

    QByteArray name;
    QByteArray password;
    ASSERT_TRUE(readBind(server.last_bind_request, &name, &password));
    EXPECT_TRUE(name.isEmpty());
    EXPECT_TRUE(password.isEmpty());

    // A real DN keeps its password.
    bound = false;
    connection.bind(QByteArrayLiteral("cn=admin,dc=example,dc=com"),
                    SecureByteArray(QByteArrayLiteral("secret")));
    ASSERT_TRUE(waitFor([&bound]() { return bound; })) << "the authenticated bind did not finish";

    ASSERT_TRUE(readBind(server.last_bind_request, &name, &password));
    EXPECT_EQ(name, QByteArrayLiteral("cn=admin,dc=example,dc=com"));
    EXPECT_EQ(password, QByteArrayLiteral("secret"));
}

//--------------------------------------------------------------------------------------------------
// A silent server holds a connection open without ever answering, so an operation can only end
// through the timeout. A refused connection would report SOCKET instead, so the listening server is
// required to reach the TIMEOUT path.
TEST(LdapConnectionTest, ReportsOperationTimeout)
{
    QTcpServer silent_server;
    ASSERT_TRUE(silent_server.listen(QHostAddress::LocalHost, 0));
    QObject::connect(&silent_server, &QTcpServer::newConnection, &silent_server, [&silent_server]()
    {
        // Accept the connection and let it sit; nothing is ever written back.
        silent_server.nextPendingConnection()->setParent(&silent_server);
    });

    LdapConnection connection;
    connection.setSecurity(LdapConnection::Security::Plain);

    bool connected = false;
    bool timed_out = false;

    QObject::connect(&connection, &LdapConnection::sig_connected, &connection,
                     [&connected]() { connected = true; });
    QObject::connect(&connection, &LdapConnection::sig_errorOccurred, &connection,
                     [&timed_out](LdapConnection::Error error, const QString&)
    {
        if (error == LdapConnection::Error::TIMEOUT)
            timed_out = true;
    });

    // The connection itself is not what is under test, so no timeout is armed around it.
    connection.connectToHost(QStringLiteral("127.0.0.1"), silent_server.serverPort());
    ASSERT_TRUE(waitFor([&connected]() { return connected; })) << "did not connect";

    connection.setOperationTimeout(MilliSeconds(100));
    connection.bind(QByteArrayLiteral("cn=admin,dc=example,dc=com"),
                    SecureByteArray(QByteArrayLiteral("secret")));

    EXPECT_TRUE(waitFor([&timed_out]() { return timed_out; })) << "the operation did not time out";
}
