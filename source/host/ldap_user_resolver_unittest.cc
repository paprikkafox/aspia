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

#include <gtest/gtest.h>

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QHostAddress>
#include <QTcpServer>
#include <QTcpSocket>

#include <functional>

#include "base/crypto/secure_string.h"
#include "base/ldap/ldap_ber.h"
#include "base/ldap/ldap_message.h"

namespace {

Database::LdapMapping mapping(const char* name, quint32 sessions)
{
    Database::LdapMapping result;
    result.name = QString::fromLatin1(name);
    result.sessions = sessions;
    return result;
}

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
bool readSearchBase(const QByteArray& message, QByteArray* base)
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

    if (!op.readElement(&tag) || tag != static_cast<quint8>(BerTag::OctetString))
        return false;

    return op.toOctetString(base);
}

//--------------------------------------------------------------------------------------------------
// The value an equality search filter asserts, such as the member DN in "(member=<user DN>)". The
// element is left empty for a filter that is not an equality, such as the presence filter a ranged
// read uses.
bool readSearchFilterValue(const QByteArray& message, QByteArray* value)
{
    value->clear();

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

    if (!op.readElement(&tag) || tag != static_cast<quint8>(BerTag::Enumerated)) // scope
        return false;

    if (!op.readElement(&tag) || tag != static_cast<quint8>(BerTag::Enumerated)) // derefAliases
        return false;

    if (!op.readElement(&tag) || tag != static_cast<quint8>(BerTag::Integer)) // sizeLimit
        return false;

    if (!op.readElement(&tag) || tag != static_cast<quint8>(BerTag::Integer)) // timeLimit
        return false;

    if (!op.readElement(&tag) || tag != static_cast<quint8>(BerTag::Boolean)) // typesOnly
        return false;

    if (!op.readElement(&tag)) // filter
        return false;

    // equalityMatch [3] is the "(attribute=value)" form; anything else carries no single value.
    if (tag != (static_cast<quint8>(BerClass::Context) | 0x20 | 0x03))
        return true;

    BerDecoder filter = op.nested();

    if (!filter.readElement(&tag) || tag != static_cast<quint8>(BerTag::OctetString)) // attribute
        return false;

    if (!filter.readElement(&tag) || tag != static_cast<quint8>(BerTag::OctetString)) // value
        return false;

    return filter.toOctetString(value);
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
// A fake directory with one service account, one user and a group per membership it is configured
// with. A bind as the service DN succeeds; a bind as the user DN succeeds only for the configured
// password. A search returns the user (with memberOf) under |user_base| and a group under
// |group_base|; a group search can be made to answer per member, so a walk through nested groups can
// be exercised.
class FakeLdapServer
{
    struct GroupAnswer
    {
        QByteArray dn;
        QByteArray name;
    };

public:
    FakeLdapServer(const QByteArray& service_dn, const QByteArray& user_dn,
                   const QByteArray& user_password, const QByteArray& user_base,
                   const QByteArray& group_base, const QByteArray& group_dn)
        : service_dn_(service_dn),
          user_dn_(user_dn),
          user_password_(user_password),
          user_base_(user_base),
          group_base_(group_base),
          group_dn_(group_dn)
    {
        member_of_value_ = group_dn_;
    }

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

    // The membership the user entry carries: a plain memberOf by default, or a ranged name such as
    // "memberOf;range=0-1499" to exercise the reader of the remaining slices.
    void setMemberOf(const QByteArray& name, const QByteArray& value)
    {
        member_of_name_ = name;
        member_of_value_ = value;
    }

    // The next slice a base-scoped read of the user entry answers with.
    void setMemberOfRange(const QByteArray& name, const QByteArray& value)
    {
        range_member_of_name_ = name;
        range_member_of_value_ = value;
    }

    // The group a group search answers with when it filters on |member_dn|. Setting any turns the
    // group answers into this lookup, so a walk through nested groups can be exercised; while none is
    // set, every group search keeps answering with the single configured group.
    void setGroupForMember(const QByteArray& member_dn, const QByteArray& group_dn,
                           const QByteArray& group_name)
    {
        GroupAnswer answer;
        answer.dn = group_dn;
        answer.name = group_name;
        groups_by_member_.insert(member_dn, answer);
    }

    int connections = 0;
    int requests = 0;

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

                bool ok = false;
                if (name == service_dn_)
                    ok = true;
                else if (name == user_dn_ && password == user_password_)
                    ok = true;

                socket->write(makeBindResponse(message_id, ok ? 0 : 49));
            }
            break;

            case LdapOp::SearchRequest:
            {
                QByteArray base;
                if (!readSearchBase(request, &base))
                    return;

                if (base == user_base_)
                {
                    socket->write(makeSearchEntry(message_id, user_dn_, member_of_name_,
                                                  member_of_value_));
                    socket->write(makeSearchDone(message_id, 0));
                }
                else if (!range_member_of_name_.isEmpty() && base == user_dn_)
                {
                    socket->write(makeSearchEntry(message_id, user_dn_, range_member_of_name_,
                                                  range_member_of_value_));
                    socket->write(makeSearchDone(message_id, 0));
                }
                else if (base == group_base_)
                {
                    answerGroupSearch(socket, request, message_id);
                }
                else
                {
                    socket->write(makeSearchDone(message_id, 0));
                }
            }
            break;

            default:
                break;
        }
    }

    void answerGroupSearch(QTcpSocket* socket, const QByteArray& request, int message_id)
    {
        // With no per-member group configured, the single-group behavior the tests above rely on
        // answers any group search with the one group.
        if (groups_by_member_.isEmpty())
        {
            socket->write(makeSearchEntry(message_id, group_dn_,
                                          QByteArrayLiteral("cn"), QByteArrayLiteral("admins")));
            socket->write(makeSearchDone(message_id, 0));
            return;
        }

        QByteArray member;
        if (readSearchFilterValue(request, &member))
        {
            const auto it = groups_by_member_.constFind(member);
            if (it != groups_by_member_.constEnd())
                socket->write(makeSearchEntry(message_id, it->dn, QByteArrayLiteral("cn"), it->name));
        }

        // A group that matches nothing simply has no members.
        socket->write(makeSearchDone(message_id, 0));
    }

    QTcpServer server_;
    QHash<QTcpSocket*, QByteArray> buffers_;

    QByteArray service_dn_;
    QByteArray user_dn_;
    QByteArray user_password_;
    QByteArray user_base_;
    QByteArray group_base_;
    QByteArray group_dn_;

    QByteArray member_of_name_ = QByteArrayLiteral("memberOf");
    QByteArray member_of_value_;
    QByteArray range_member_of_name_;
    QByteArray range_member_of_value_;
    QHash<QByteArray, GroupAnswer> groups_by_member_;
};

} // namespace

//--------------------------------------------------------------------------------------------------
TEST(LdapMapSessionsTest, HighestPrivilegeWins)
{
    const QVector<Database::LdapMapping> groups = {
        mapping("cn=view,dc=x", 1),        // SESSION_TYPE_DESKTOP
        mapping("cn=control,dc=x", 1 | 32) // DESKTOP | TERMINAL
    };

    EXPECT_EQ(ldapMapSessions(groups, {}, QStringLiteral("jdoe"), { QStringLiteral("cn=view,dc=x") },
                              0, true), 1u);
    EXPECT_EQ(ldapMapSessions(groups, {}, QStringLiteral("jdoe"),
                              { QStringLiteral("cn=control,dc=x") }, 0, true), (1u | 32u));

    // Membership in both groups combines with a bitwise OR.
    EXPECT_EQ(ldapMapSessions(groups, {}, QStringLiteral("jdoe"),
                              { QStringLiteral("cn=view,dc=x"), QStringLiteral("cn=control,dc=x") },
                              0, true), (1u | 32u));
}

//--------------------------------------------------------------------------------------------------
TEST(LdapMapSessionsTest, UserMappingCombinesWithGroups)
{
    const QVector<Database::LdapMapping> groups = { mapping("cn=view,dc=x", 1) };
    const QVector<Database::LdapMapping> users = { mapping("jdoe", 1 | 32) };

    EXPECT_EQ(ldapMapSessions(groups, users, QStringLiteral("jdoe"),
                              { QStringLiteral("cn=view,dc=x") }, 0, true), (1u | 32u));
}

//--------------------------------------------------------------------------------------------------
TEST(LdapMapSessionsTest, UnmatchedUsesDefaultOrDenies)
{
    const QVector<Database::LdapMapping> groups = { mapping("cn=view,dc=x", 1) };

    EXPECT_EQ(ldapMapSessions(groups, {}, QStringLiteral("other"), {}, 0, true), 0u);
    EXPECT_EQ(ldapMapSessions(groups, {}, QStringLiteral("other"), {}, 8u, false), 8u);
}

//--------------------------------------------------------------------------------------------------
// The out parameter says whether anything named the login at all, which is what tells "this login is
// in no list" apart from "what names it grants it no rights".
TEST(LdapMapSessionsTest, ReportsWhetherAnythingMatched)
{
    const QVector<Database::LdapMapping> groups = { mapping("cn=view,dc=x", 1) };
    const QVector<Database::LdapMapping> users = { mapping("jdoe", 0) };

    bool matched = true;
    EXPECT_EQ(ldapMapSessions(groups, users, QStringLiteral("other"), {}, 0, true, &matched), 0u);
    EXPECT_FALSE(matched);

    // An entry that grants nothing is still a match.
    matched = false;
    EXPECT_EQ(ldapMapSessions(groups, users, QStringLiteral("jdoe"), {}, 0, true, &matched), 0u);
    EXPECT_TRUE(matched);

    // So is a group the login is in.
    matched = false;
    EXPECT_EQ(ldapMapSessions(groups, users, QStringLiteral("someone"),
                              { QStringLiteral("cn=view,dc=x") }, 0, true, &matched), 1u);
    EXPECT_TRUE(matched);
}

//--------------------------------------------------------------------------------------------------
TEST(LdapMapSessionsTest, MatchingIsCaseInsensitive)
{
    const QVector<Database::LdapMapping> groups = { mapping("cn=view,dc=x", 1) };

    EXPECT_EQ(ldapMapSessions(groups, {}, QStringLiteral("JDOE"), { QStringLiteral("CN=VIEW,DC=X") },
                              0, true), 1u);
}

//--------------------------------------------------------------------------------------------------
TEST(LdapUserResolverTest, ResolvesUserThroughLdap)
{
    FakeLdapServer server(QByteArrayLiteral("cn=service,dc=x"), QByteArrayLiteral("uid=jdoe,ou=users,dc=x"),
                          QByteArrayLiteral("user-password"), QByteArrayLiteral("ou=users,dc=x"),
                          QByteArrayLiteral("ou=groups,dc=x"), QByteArrayLiteral("cn=admins,dc=x"));
    ASSERT_TRUE(server.listen());

    Database::LdapConfig config;
    config.enabled = true;
    config.server = QStringLiteral("127.0.0.1");
    config.port = server.port();
    config.security = Database::LdapSecurity::PLAIN;
    config.verify_peer = false;
    config.bind_dn = QStringLiteral("cn=service,dc=x");
    config.bind_password = QStringLiteral("service-password");
    config.base_dn = QStringLiteral("ou=users,dc=x");
    config.user_filter = QStringLiteral("(&(objectClass=person)(uid=%1))");
    config.user_name_attribute = QStringLiteral("uid");
    config.group_attribute = QStringLiteral("cn");
    config.group_base_dn = QStringLiteral("ou=groups,dc=x");
    config.group_nested = false;

    LdapUserResolver resolver;
    resolver.setConfig(config);
    resolver.setMappings({ mapping("admins", 1 | 32) }, {});

    QString resolved_name;
    quint32 resolved_sessions = 0;
    bool denied = false;
    bool fallback = false;

    QObject::connect(&resolver, &LdapUserResolver::sig_resolved, &resolver,
                     [&](const QString& name, quint32 sessions)
    {
        resolved_name = name;
        resolved_sessions = sessions;
    });
    QObject::connect(&resolver, &LdapUserResolver::sig_denied, &resolver, [&]() { denied = true; });
    QObject::connect(&resolver, &LdapUserResolver::sig_fallbackToLocal, &resolver,
                     [&]() { fallback = true; });

    resolver.resolve(QStringLiteral("jdoe"), SecureString(QStringLiteral("user-password")));

    ASSERT_TRUE(waitFor([&]() { return resolved_sessions != 0 || denied || fallback; }))
        << "resolver did not finish";

    EXPECT_FALSE(denied);
    EXPECT_FALSE(fallback);
    EXPECT_EQ(resolved_name, QStringLiteral("jdoe"));
    EXPECT_EQ(resolved_sessions, (1u | 32u));
}

//--------------------------------------------------------------------------------------------------
TEST(LdapUserResolverTest, WrongPasswordIsDenied)
{
    FakeLdapServer server(QByteArrayLiteral("cn=service,dc=x"), QByteArrayLiteral("uid=jdoe,ou=users,dc=x"),
                          QByteArrayLiteral("user-password"), QByteArrayLiteral("ou=users,dc=x"),
                          QByteArrayLiteral("ou=groups,dc=x"), QByteArrayLiteral("cn=admins,dc=x"));
    ASSERT_TRUE(server.listen());

    Database::LdapConfig config;
    config.enabled = true;
    config.server = QStringLiteral("127.0.0.1");
    config.port = server.port();
    config.security = Database::LdapSecurity::PLAIN;
    config.verify_peer = false;
    config.bind_dn = QStringLiteral("cn=service,dc=x");
    config.bind_password = QStringLiteral("service-password");
    config.base_dn = QStringLiteral("ou=users,dc=x");
    config.user_filter = QStringLiteral("(&(objectClass=person)(uid=%1))");
    config.user_name_attribute = QStringLiteral("uid");
    config.group_attribute = QStringLiteral("cn");
    config.group_base_dn = QStringLiteral("ou=groups,dc=x");
    config.group_nested = false;

    LdapUserResolver resolver;
    resolver.setConfig(config);
    resolver.setMappings({ mapping("admins", 1) }, {});

    bool denied = false;
    bool fallback = false;
    quint32 resolved_sessions = 0;

    QObject::connect(&resolver, &LdapUserResolver::sig_resolved, &resolver,
                     [&](const QString&, quint32 sessions) { resolved_sessions = sessions; });
    QObject::connect(&resolver, &LdapUserResolver::sig_denied, &resolver, [&]() { denied = true; });
    QObject::connect(&resolver, &LdapUserResolver::sig_fallbackToLocal, &resolver,
                     [&]() { fallback = true; });

    resolver.resolve(QStringLiteral("jdoe"), SecureString(QStringLiteral("wrong")));

    ASSERT_TRUE(waitFor([&]() { return denied || fallback || resolved_sessions != 0; }))
        << "resolver did not finish";

    EXPECT_TRUE(denied);
    EXPECT_FALSE(fallback);
}

//--------------------------------------------------------------------------------------------------
// Without the AD matching rule the resolver walks the group tree itself: the user names one group,
// that group names another, and the mapping has to see both names.
TEST(LdapUserResolverTest, WalksNestedGroupsWithoutMatchingRule)
{
    const QByteArray user_dn = QByteArrayLiteral("uid=jdoe,ou=users,dc=example,dc=com");
    const QByteArray group_dn = QByteArrayLiteral("cn=admins,ou=groups,dc=example,dc=com");
    const QByteArray nested_dn = QByteArrayLiteral("cn=helpdesk,ou=groups,dc=example,dc=com");

    FakeLdapServer server(QByteArrayLiteral("cn=service,dc=example,dc=com"), user_dn,
                          QByteArrayLiteral("secret"),
                          QByteArrayLiteral("ou=users,dc=example,dc=com"),
                          QByteArrayLiteral("ou=groups,dc=example,dc=com"), group_dn);
    // The user names the first group, and the first group names the second.
    server.setGroupForMember(user_dn, group_dn, QByteArrayLiteral("admins"));
    server.setGroupForMember(group_dn, nested_dn, QByteArrayLiteral("helpdesk"));
    ASSERT_TRUE(server.listen());

    Database::LdapConfig config;
    config.enabled = true;
    config.server = QStringLiteral("127.0.0.1");
    config.port = server.port();
    config.security = Database::LdapSecurity::PLAIN;
    config.verify_peer = false;
    config.bind_dn = QStringLiteral("cn=service,dc=example,dc=com");
    config.bind_password = QStringLiteral("secret");
    config.base_dn = QStringLiteral("ou=users,dc=example,dc=com");
    config.user_filter = QStringLiteral("(&(objectClass=person)(uid=%1))");
    config.user_name_attribute = QStringLiteral("uid");
    config.group_attribute = QStringLiteral("cn");
    config.group_base_dn = QStringLiteral("ou=groups,dc=example,dc=com");
    config.group_nested = false;

    LdapUserResolver resolver;
    resolver.setConfig(config);
    resolver.setMappings({ mapping("admins", 1), mapping("helpdesk", 4) }, {});

    QString resolved_name;
    quint32 resolved_sessions = 0;
    bool denied = false;
    bool fallback = false;

    QObject::connect(&resolver, &LdapUserResolver::sig_resolved, &resolver,
                     [&](const QString& name, quint32 sessions)
    {
        resolved_name = name;
        resolved_sessions = sessions;
    });
    QObject::connect(&resolver, &LdapUserResolver::sig_denied, &resolver, [&]() { denied = true; });
    QObject::connect(&resolver, &LdapUserResolver::sig_fallbackToLocal, &resolver,
                     [&]() { fallback = true; });

    resolver.resolve(QStringLiteral("jdoe"), SecureString(QStringLiteral("secret")));

    ASSERT_TRUE(waitFor([&]() { return resolved_sessions != 0 || denied || fallback; }))
        << "resolver did not finish";

    EXPECT_FALSE(denied);
    EXPECT_FALSE(fallback);
    EXPECT_EQ(resolved_name, QStringLiteral("jdoe"));

    // Both the direct membership and the group it reaches count towards the mapping.
    EXPECT_EQ(resolved_sessions, (1u | 4u));
}

//--------------------------------------------------------------------------------------------------
// Active Directory hands out a long memberOf in slices: the first answer names the attribute with a
// range, and the rest is read from the user entry by name. Both slices have to reach the mapping.
TEST(LdapUserResolverTest, ReadsRangedMemberOf)
{
    const QByteArray user_dn = QByteArrayLiteral("uid=jdoe,ou=users,dc=example,dc=com");
    const QByteArray group_dn = QByteArrayLiteral("cn=admins,ou=groups,dc=example,dc=com");
    const QByteArray second_dn = QByteArrayLiteral("cn=helpdesk,ou=groups,dc=example,dc=com");

    FakeLdapServer server(QByteArrayLiteral("cn=service,dc=example,dc=com"), user_dn,
                          QByteArrayLiteral("secret"),
                          QByteArrayLiteral("ou=users,dc=example,dc=com"),
                          QByteArrayLiteral("ou=groups,dc=example,dc=com"), group_dn);
    // The user search carries the first slice; the base-scoped follow-up carries the second.
    server.setMemberOf(QByteArrayLiteral("memberOf;range=0-1499"), group_dn);
    server.setMemberOfRange(QByteArrayLiteral("memberOf;range=1500-*"), second_dn);
    ASSERT_TRUE(server.listen());

    Database::LdapConfig config;
    config.enabled = true;
    config.server = QStringLiteral("127.0.0.1");
    config.port = server.port();
    config.security = Database::LdapSecurity::PLAIN;
    config.verify_peer = false;
    config.bind_dn = QStringLiteral("cn=service,dc=example,dc=com");
    config.bind_password = QStringLiteral("secret");
    config.base_dn = QStringLiteral("ou=users,dc=example,dc=com");
    config.user_filter = QStringLiteral("(&(objectClass=person)(uid=%1))");
    config.user_name_attribute = QStringLiteral("uid");
    config.group_attribute = QStringLiteral("cn");
    // The slices carry the whole membership, so no group search is needed.
    config.group_base_dn = QString();
    config.group_nested = false;

    LdapUserResolver resolver;
    resolver.setConfig(config);
    resolver.setMappings({ mapping("admins", 1), mapping("helpdesk", 4) }, {});

    QString resolved_name;
    quint32 resolved_sessions = 0;
    bool denied = false;
    bool fallback = false;

    QObject::connect(&resolver, &LdapUserResolver::sig_resolved, &resolver,
                     [&](const QString& name, quint32 sessions)
    {
        resolved_name = name;
        resolved_sessions = sessions;
    });
    QObject::connect(&resolver, &LdapUserResolver::sig_denied, &resolver, [&]() { denied = true; });
    QObject::connect(&resolver, &LdapUserResolver::sig_fallbackToLocal, &resolver,
                     [&]() { fallback = true; });

    resolver.resolve(QStringLiteral("jdoe"), SecureString(QStringLiteral("secret")));

    ASSERT_TRUE(waitFor([&]() { return resolved_sessions != 0 || denied || fallback; }))
        << "resolver did not finish";

    EXPECT_FALSE(denied);
    EXPECT_FALSE(fallback);
    EXPECT_EQ(resolved_name, QStringLiteral("jdoe"));

    // Both the first and the second slice of memberOf count towards the mapping.
    EXPECT_EQ(resolved_sessions, (1u | 4u));
}
