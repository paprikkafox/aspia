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

#ifndef BASE_PEER_SERVER_AUTHENTICATOR_H
#define BASE_PEER_SERVER_AUTHENTICATOR_H

#include <memory>

#include "base/shared_pointer.h"
#include "base/crypto/big_num.h"
#include "base/crypto/key_pair.h"
#include "base/peer/authenticator.h"
#include "base/peer/user_list.h"

class CredentialResolver;
class SecureString;

class ServerAuthenticator final : public Authenticator
{
    Q_OBJECT

public:
    explicit ServerAuthenticator(QObject* parent = nullptr);
    ~ServerAuthenticator() final;

    enum class AnonymousAccess
    {
        ENABLE, // Anonymous access is enabled.
        DISABLE // Anonymous access is disabled.
    };

    enum class PasswordAuth
    {
        DISABLE,   // The password method is not offered.
        EPHEMERAL, // Offered on an already authenticated transport (router/relay).
        HOST_KEY   // Offered and authenticated by the host's long-term key (direct).
    };

    // Sets the user list.
    void setUserList(SharedPointer<UserList> user_list);

    // Selects how the password (IDENTIFY_PASSWORD) method is handled. By default it is disabled.
    void setPasswordAuth(PasswordAuth password_auth);

    // Sets the private key.
    [[nodiscard]] bool setPrivateKey(const SecureByteArray& private_key);

    // Enables or disables anonymous access.
    // |session_types] allowed session types for anonymous access.
    // The private key must be set up for anonymous access.
    // By default, anonymous access is disabled.
    [[nodiscard]] bool setAnonymousAccess(AnonymousAccess anonymous_access, quint32 session_types);

protected:
    // Authenticator implementation.
    [[nodiscard]] bool onStarted() final;
    void onReceived(const QByteArray& buffer) final;
    [[nodiscard]] QByteArray keyLabel(Direction direction) const final;

private:
    void onClientHello(const QByteArray& buffer);
    void onIdentify(const QByteArray& buffer);
    void onClientKeyExchange(const QByteArray& buffer);
    void onPasswordIdentify(const QByteArray& buffer);
    void doSessionChallenge();
    void onSessionResponse(const QByteArray& buffer);
    [[nodiscard]] QByteArray createSrpKey();

    // Selects the identification method from the client's capabilities and the host configuration.
    // Returns false (and finishes with an error) when nothing can be selected.
    [[nodiscard]] bool selectIdentifyMethod(quint32 client_methods);

    // CredentialResolver results for the password method.
    void onCredentialsResolved(const QString& user_name, quint32 sessions);
    void onCredentialsDenied();

    SharedPointer<UserList> user_list_;

    enum class InternalState
    {
        READ_CLIENT_HELLO,
        READ_IDENTIFY,
        READ_CLIENT_KEY_EXCHANGE,
        READ_PASSWORD_IDENTIFY,
        READ_SESSION_RESPONSE
    };

    AnonymousAccess anonymous_access_ = AnonymousAccess::DISABLE;
    PasswordAuth password_auth_ = PasswordAuth::DISABLE;
    InternalState internal_state_ = InternalState::READ_CLIENT_HELLO;

    // Bitmask of allowed session types.
    quint32 session_types_ = 0;

    KeyPair key_pair_;

    // The resolver driving the password (IDENTIFY_PASSWORD) path; created when that method is
    // selected.
    std::unique_ptr<CredentialResolver> credential_resolver_;

    BigNum N_;
    BigNum g_;
    BigNum v_;
    BigNum s_;
    BigNum b_;
    BigNum B_;
    BigNum A_;

    Q_DISABLE_COPY_MOVE(ServerAuthenticator)
};

#endif // BASE_PEER_SERVER_AUTHENTICATOR_H
