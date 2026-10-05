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

#include <gtest/gtest.h>

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QHash>
#include <QHostAddress>
#include <QTcpServer>
#include <QTcpSocket>

#include <functional>

#include "base/crypto/secure_string.h"
#include "base/ldap/ldap_ber.h"
#include "base/ldap/ldap_message.h"

namespace {

// The placeholder directory the fake server serves. Nothing here is real.
const char kServiceDn[] = "cn=service,dc=example,dc=com";
const char kServicePassword[] = "service-secret";
const char kUserDn[] = "uid=jdoe,ou=users,dc=example,dc=com";
const char kUserLogin[] = "jdoe";
const char kUserPassword[] = "secret";
const char kUserDisplayName[] = "John Doe";
const char kUserBase[] = "ou=users,dc=example,dc=com";
const char kGhostDn[] = "uid=ghost,ou=users,dc=example,dc=com";
const char kUserLoginAttribute[] = "uid";
const char kGroupBase[] = "ou=groups,dc=example,dc=com";
const char kGroupDn[] = "cn=admins,ou=groups,dc=example,dc=com";
const char kGroupName[] = "admins";
const char kGroupDescription[] = "The administrators";
const char kGroupAttribute[] = "cn";

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
bool readMessageHeader(const QByteArray& message, int* message_id, quint8* op)
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
// Reads the search base and says whether the request is paged. A listing is fetched in pages (the
// query asks with the paged results control), while the search for a login to bind as is a single
// request, so the two are told apart on the same base; the group listing uses a base of its own.
bool readSearchRequest(const QByteArray& message, QByteArray* base, bool* paged)
{
    BerDecoder decoder(message);
    quint8 tag = 0;

    if (!decoder.readElement(&tag) || tag != static_cast<quint8>(BerTag::Sequence))
        return false;

    BerDecoder body = decoder.nested();

    if (!body.readElement(&tag) || tag != static_cast<quint8>(BerTag::Integer)) // message id
        return false;

    if (!body.readElement(&tag) || tag != static_cast<quint8>(LdapOp::SearchRequest))
        return false;

    BerDecoder op = body.nested();

    if (!op.readElement(&tag) || tag != static_cast<quint8>(BerTag::OctetString)) // base
        return false;
    if (!op.toOctetString(base))
        return false;

    // Skip scope, derefAliases, sizeLimit, timeLimit, typesOnly, the filter and the attributes; the
    // optional controls then follow the search request in the message body.
    for (int i = 0; i < 7; ++i)
    {
        if (!op.readElement(&tag))
            return false;
    }

    *paged = !body.atEnd();
    return true;
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
// One attribute of a fake entry: a name and a single value.
struct FakeAttribute
{
    QByteArray name;
    QByteArray value;
};

//--------------------------------------------------------------------------------------------------
QByteArray makeSearchEntry(int message_id, const QByteArray& object_name,
                           const QList<FakeAttribute>& attributes)
{
    BerEncoder attribute_list;
    for (const FakeAttribute& attribute : attributes)
    {
        BerEncoder values;
        values.writeOctetString(attribute.value);

        BerEncoder set;
        set.writeSet(values.data());

        BerEncoder partial;
        partial.writeOctetString(attribute.name);
        partial.writeRaw(set.data());

        BerEncoder partial_attribute;
        partial_attribute.writeSequence(partial.data());

        attribute_list.writeRaw(partial_attribute.data());
    }

    BerEncoder attributes_sequence;
    attributes_sequence.writeSequence(attribute_list.data());

    BerEncoder entry;
    entry.writeOctetString(object_name);
    entry.writeRaw(attributes_sequence.data());

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
// A fake directory for the query: it serves a service account, one user and one group, and answers a
// search by its base. The user listing carries a display name and the login, plus a second entry that
// has no login attribute and must be skipped; the group listing carries the name and a description.
// The user bind succeeds only for the configured password. A size cap on the listing and the code of
// a failed user bind can both be shaped by a test.
class FakeLdapServer
{
public:
    bool listen()
    {
        QObject::connect(&server_, &QTcpServer::newConnection, &server_, [this]()
        {
            ++connections;
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

    int connections = 0;
    int requests = 0;

    bool send_loginless_entry = true; // A second user with no login attribute; it must be skipped.
    bool login_found = true;          // Whether the login search returns a user at all.
    int list_result_code = 0;         // The code of the listing done (4 is sizeLimitExceeded).
    int user_bind_code = 49;          // The code of a user bind whose password does not match.

private:
    void respond(QTcpSocket* socket, const QByteArray& request)
    {
        int message_id = 0;
        quint8 op = 0;
        if (!readMessageHeader(request, &message_id, &op))
            return;

        ++requests;

        switch (static_cast<LdapOp>(op))
        {
            case LdapOp::BindRequest:
            {
                QByteArray name;
                QByteArray password;
                if (!readBind(request, &name, &password))
                    return;

                int code = 49;
                if (name == QByteArray(kServiceDn))
                    code = 0;
                else if (name == QByteArray(kUserDn))
                    code = password == QByteArray(kUserPassword) ? 0 : user_bind_code;

                socket->write(makeBindResponse(message_id, code));
            }
            break;

            case LdapOp::SearchRequest:
            {
                QByteArray base;
                bool paged = false;
                if (!readSearchRequest(request, &base, &paged))
                    return;

                if (base == QByteArray(kGroupBase))
                {
                    socket->write(makeSearchEntry(message_id, QByteArray(kGroupDn),
                    {
                        { QByteArray(kGroupAttribute), QByteArray(kGroupName) },
                        { QByteArrayLiteral("description"), QByteArray(kGroupDescription) }
                    }));
                    socket->write(makeSearchDone(message_id, 0));
                }
                else if (paged)
                {
                    socket->write(makeSearchEntry(message_id, QByteArray(kUserDn),
                    {
                        { QByteArrayLiteral("displayName"), QByteArray(kUserDisplayName) },
                        { QByteArray(kUserLoginAttribute), QByteArray(kUserLogin) }
                    }));

                    if (send_loginless_entry)
                    {
                        socket->write(makeSearchEntry(message_id, QByteArray(kGhostDn),
                        {
                            { QByteArrayLiteral("displayName"), QByteArrayLiteral("Ghost Account") }
                        }));
                    }

                    socket->write(makeSearchDone(message_id, list_result_code));
                }
                else
                {
                    if (login_found)
                    {
                        socket->write(makeSearchEntry(message_id, QByteArray(kUserDn),
                        {
                            { QByteArray(kUserLoginAttribute), QByteArray(kUserLogin) }
                        }));
                    }

                    socket->write(makeSearchDone(message_id, 0));
                }
            }
            break;

            default:
                break;
        }
    }

    QTcpServer server_;
    QHash<QTcpSocket*, QByteArray> buffers_;
};

//--------------------------------------------------------------------------------------------------
// The settings that point at the fake server, with a login placeholder in the user filter and a base
// of their own for the groups.
Database::LdapConfig makeConfig(quint16 port)
{
    Database::LdapConfig config;
    config.enabled = true;
    config.server = QStringLiteral("127.0.0.1");
    config.port = port;
    config.security = Database::LdapSecurity::PLAIN;
    config.verify_peer = false;
    config.bind_dn = QString::fromLatin1(kServiceDn);
    config.bind_password = QString::fromLatin1(kServicePassword);
    config.base_dn = QString::fromLatin1(kUserBase);
    config.user_filter = QStringLiteral("(&(objectClass=person)(uid=%1))");
    config.user_name_attribute = QString::fromLatin1(kUserLoginAttribute);
    config.group_filter = QStringLiteral("(objectClass=group)");
    config.group_base_dn = QString::fromLatin1(kGroupBase);
    config.group_attribute = QString::fromLatin1(kGroupAttribute);
    return config;
}

} // namespace

//--------------------------------------------------------------------------------------------------
TEST(LdapDirectoryQueryTest, SearchUsersListsNamesAndLogins)
{
    FakeLdapServer server;
    ASSERT_TRUE(server.listen());

    const Database::LdapConfig config = makeConfig(server.port());

    LdapDirectoryQuery query;
    QVector<LdapDirectoryQuery::Entry> entries;
    bool found = false;
    bool failed = false;

    QObject::connect(&query, &LdapDirectoryQuery::sig_entriesFound, &query,
                     [&](const QVector<LdapDirectoryQuery::Entry>& result)
    {
        entries = result;
        found = true;
    });
    QObject::connect(&query, &LdapDirectoryQuery::sig_failed, &query,
                     [&](const QString&) { failed = true; });

    query.search(config, LdapDirectoryQuery::Kind::USER);

    ASSERT_TRUE(waitFor([&]() { return found || failed; })) << "the listing did not finish";
    ASSERT_FALSE(failed);

    // The entry without the login attribute is of no use and is left out.
    ASSERT_EQ(entries.size(), 1);
    EXPECT_EQ(entries.first().name, QString::fromLatin1(kUserDisplayName));
    EXPECT_EQ(entries.first().login, QString::fromLatin1(kUserLogin));
    EXPECT_EQ(entries.first().dn, QString::fromLatin1(kUserDn));
}

//--------------------------------------------------------------------------------------------------
TEST(LdapDirectoryQueryTest, SearchGroupsListsNamesAndDescriptions)
{
    FakeLdapServer server;
    ASSERT_TRUE(server.listen());

    const Database::LdapConfig config = makeConfig(server.port());

    LdapDirectoryQuery query;
    QVector<LdapDirectoryQuery::Entry> entries;
    bool found = false;
    bool failed = false;

    QObject::connect(&query, &LdapDirectoryQuery::sig_entriesFound, &query,
                     [&](const QVector<LdapDirectoryQuery::Entry>& result)
    {
        entries = result;
        found = true;
    });
    QObject::connect(&query, &LdapDirectoryQuery::sig_failed, &query,
                     [&](const QString&) { failed = true; });

    query.search(config, LdapDirectoryQuery::Kind::GROUP);

    ASSERT_TRUE(waitFor([&]() { return found || failed; })) << "the listing did not finish";
    ASSERT_FALSE(failed);

    ASSERT_EQ(entries.size(), 1);
    EXPECT_EQ(entries.first().name, QString::fromLatin1(kGroupName));
    EXPECT_EQ(entries.first().description, QString::fromLatin1(kGroupDescription));
    EXPECT_EQ(entries.first().dn, QString::fromLatin1(kGroupDn));
}

//--------------------------------------------------------------------------------------------------
// A directory that caps a listing still sends what fits; the entries that arrived are reported
// instead of the whole operation failing.
TEST(LdapDirectoryQueryTest, SearchReportsArrivedEntriesOnSizeLimitExceeded)
{
    FakeLdapServer server;
    server.list_result_code = 4; // sizeLimitExceeded
    ASSERT_TRUE(server.listen());

    const Database::LdapConfig config = makeConfig(server.port());

    LdapDirectoryQuery query;
    QVector<LdapDirectoryQuery::Entry> entries;
    bool found = false;
    bool failed = false;

    QObject::connect(&query, &LdapDirectoryQuery::sig_entriesFound, &query,
                     [&](const QVector<LdapDirectoryQuery::Entry>& result)
    {
        entries = result;
        found = true;
    });
    QObject::connect(&query, &LdapDirectoryQuery::sig_failed, &query,
                     [&](const QString&) { failed = true; });

    query.search(config, LdapDirectoryQuery::Kind::USER);

    ASSERT_TRUE(waitFor([&]() { return found || failed; })) << "the listing did not finish";
    EXPECT_FALSE(failed);

    ASSERT_EQ(entries.size(), 1);
    EXPECT_EQ(entries.first().login, QString::fromLatin1(kUserLogin));
}

//--------------------------------------------------------------------------------------------------
TEST(LdapDirectoryQueryTest, CheckLoginSucceedsForExistingLogin)
{
    FakeLdapServer server;
    ASSERT_TRUE(server.listen());

    const Database::LdapConfig config = makeConfig(server.port());

    LdapDirectoryQuery query;
    bool checked = false;
    bool success = false;
    int code = -1;
    QString user_dn;
    bool failed = false;

    QObject::connect(&query, &LdapDirectoryQuery::sig_loginChecked, &query,
                     [&](bool ok, int result_code, const QString&, const QString& dn)
    {
        success = ok;
        code = result_code;
        user_dn = dn;
        checked = true;
    });
    QObject::connect(&query, &LdapDirectoryQuery::sig_failed, &query,
                     [&](const QString&) { failed = true; });

    query.checkLogin(config, QString::fromLatin1(kUserLogin),
                     SecureString(QString::fromLatin1(kUserPassword)));

    ASSERT_TRUE(waitFor([&]() { return checked || failed; })) << "the check did not finish";
    ASSERT_FALSE(failed);

    EXPECT_TRUE(success);
    EXPECT_EQ(code, 0);
    EXPECT_EQ(user_dn, QString::fromLatin1(kUserDn));
}

//--------------------------------------------------------------------------------------------------
TEST(LdapDirectoryQueryTest, CheckLoginFailsForWrongPassword)
{
    FakeLdapServer server;
    server.user_bind_code = 49; // invalidCredentials
    ASSERT_TRUE(server.listen());

    const Database::LdapConfig config = makeConfig(server.port());

    LdapDirectoryQuery query;
    bool checked = false;
    bool success = true;
    int code = -1;
    QString user_dn;
    bool failed = false;

    QObject::connect(&query, &LdapDirectoryQuery::sig_loginChecked, &query,
                     [&](bool ok, int result_code, const QString&, const QString& dn)
    {
        success = ok;
        code = result_code;
        user_dn = dn;
        checked = true;
    });
    QObject::connect(&query, &LdapDirectoryQuery::sig_failed, &query,
                     [&](const QString&) { failed = true; });

    query.checkLogin(config, QString::fromLatin1(kUserLogin),
                     SecureString(QStringLiteral("wrong")));

    ASSERT_TRUE(waitFor([&]() { return checked || failed; })) << "the check did not finish";
    ASSERT_FALSE(failed);

    EXPECT_FALSE(success);
    EXPECT_EQ(code, 49);
    EXPECT_EQ(user_dn, QString::fromLatin1(kUserDn));
}

//--------------------------------------------------------------------------------------------------
// A login the directory has no object for is not a failure of the operation: it is reported as its own
// result, with no distinguished name to bind as.
TEST(LdapDirectoryQueryTest, CheckLoginReportsUnknownLogin)
{
    FakeLdapServer server;
    server.login_found = false;
    ASSERT_TRUE(server.listen());

    const Database::LdapConfig config = makeConfig(server.port());

    LdapDirectoryQuery query;
    bool checked = false;
    bool success = true;
    int code = 0;
    QString user_dn;
    bool failed = false;

    QObject::connect(&query, &LdapDirectoryQuery::sig_loginChecked, &query,
                     [&](bool ok, int result_code, const QString&, const QString& dn)
    {
        success = ok;
        code = result_code;
        user_dn = dn;
        checked = true;
    });
    QObject::connect(&query, &LdapDirectoryQuery::sig_failed, &query,
                     [&](const QString&) { failed = true; });

    query.checkLogin(config, QStringLiteral("nobody"), SecureString(QStringLiteral("secret")));

    ASSERT_TRUE(waitFor([&]() { return checked || failed; })) << "the check did not finish";
    ASSERT_FALSE(failed);

    EXPECT_FALSE(success);
    EXPECT_EQ(code, LdapDirectoryQuery::kLoginNotFound);
    EXPECT_TRUE(user_dn.isEmpty());
}

//--------------------------------------------------------------------------------------------------
// Without a server there is nothing to connect to, so the failure is reported at once and no other
// signal follows.
TEST(LdapDirectoryQueryTest, FailsWithoutServer)
{
    Database::LdapConfig config = makeConfig(0);
    config.server.clear();

    LdapDirectoryQuery query;
    QString message;
    bool found = false;
    bool checked = false;

    QObject::connect(&query, &LdapDirectoryQuery::sig_failed, &query,
                     [&](const QString& text) { message = text; });
    QObject::connect(&query, &LdapDirectoryQuery::sig_entriesFound, &query,
                     [&](const QVector<LdapDirectoryQuery::Entry>&) { found = true; });
    QObject::connect(&query, &LdapDirectoryQuery::sig_loginChecked, &query,
                     [&](bool, int, const QString&, const QString&) { checked = true; });

    query.search(config, LdapDirectoryQuery::Kind::USER);

    ASSERT_TRUE(waitFor([&]() { return !message.isEmpty(); })) << "the failure was not reported";
    EXPECT_FALSE(found);
    EXPECT_FALSE(checked);
}

//--------------------------------------------------------------------------------------------------
TEST(LdapDirectoryQueryTest, FailsWithoutBaseDn)
{
    Database::LdapConfig config = makeConfig(0);
    config.server = QStringLiteral("127.0.0.1");
    config.base_dn.clear();

    LdapDirectoryQuery query;
    QString message;
    bool found = false;
    bool checked = false;

    QObject::connect(&query, &LdapDirectoryQuery::sig_failed, &query,
                     [&](const QString& text) { message = text; });
    QObject::connect(&query, &LdapDirectoryQuery::sig_entriesFound, &query,
                     [&](const QVector<LdapDirectoryQuery::Entry>&) { found = true; });
    QObject::connect(&query, &LdapDirectoryQuery::sig_loginChecked, &query,
                     [&](bool, int, const QString&, const QString&) { checked = true; });

    query.search(config, LdapDirectoryQuery::Kind::USER);

    ASSERT_TRUE(waitFor([&]() { return !message.isEmpty(); })) << "the failure was not reported";
    EXPECT_FALSE(found);
    EXPECT_FALSE(checked);
}
