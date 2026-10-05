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

#ifndef BASE_PEER_CLIENT_AUTHENTICATOR_H
#define BASE_PEER_CLIENT_AUTHENTICATOR_H

#include "base/crypto/big_num.h"
#include "base/crypto/key_pair.h"
#include "base/crypto/secure_string.h"
#include "base/peer/authenticator.h"

class ClientAuthenticator final : public Authenticator
{
    Q_OBJECT

public:
    explicit ClientAuthenticator(QObject* parent = nullptr);
    ~ClientAuthenticator() final;

    void setPeerPublicKey(const QByteArray& public_key);
    void setIdentify(proto::key_exchange::Identify identify);

    // How the password (IDENTIFY_PASSWORD) method may be used: disabled, over an already
    // authenticated transport (EPHEMERAL), or authenticated by the host's long-term key (HOST_KEY).
    enum class PasswordAuth
    {
        DISABLE,
        EPHEMERAL,
        HOST_KEY
    };
    void setPasswordAuth(PasswordAuth password_auth);

    void setUserName(const QString& username);
    void setPassword(const SecureString& password);
    void setSessionType(quint32 session_type);
    void setDisplayName(const QString& display_name);
    void setProbe(bool probe);

    // The host's long-term public key used by the password method (verified against the pinned key,
    // or pinned by the caller on first use). Empty until ServerHello has been processed.
    [[nodiscard]] QByteArray hostPublicKey() const { return host_public_key_; }

signals:
    // Emitted once, when the password method pins the host's long-term key (TOFU): the host
    // presented a key the client did not know and the handshake succeeded. The caller stores the
    // key, so later connections verify the same host.
    void sig_hostKeyLearned(const QByteArray& public_key);

protected:
    // Authenticator implementation.
    [[nodiscard]] bool onStarted() final;
    void onReceived(const QByteArray& buffer) final;
    [[nodiscard]] QByteArray keyLabel(Direction direction) const final;

private:
    void sendClientHello();
    [[nodiscard]] bool readServerHello(const QByteArray& buffer);
    void sendIdentify();
    void sendPasswordIdentify();
    [[nodiscard]] bool readServerKeyExchange(const QByteArray& buffer);
    void sendClientKeyExchange();
    [[nodiscard]] bool readSessionChallenge(const QByteArray& buffer);
    void sendSessionResponse();

    enum class InternalState
    {
        READ_SERVER_HELLO,
        READ_SERVER_KEY_EXCHANGE,
        READ_SESSION_CHALLENGE
    };

    InternalState internal_state_ = InternalState::READ_SERVER_HELLO;

    QByteArray peer_public_key_;
    QString username_;
    SecureString password_;
    QString display_name_;

    PasswordAuth password_auth_ = PasswordAuth::DISABLE;

    // Kept until readServerHello, so the transcript can be assembled in the order the selected
    // method requires (the secret before or after ClientHello).
    QByteArray client_hello_;

    // The host key used by the password method over a direct connection.
    QByteArray host_public_key_;

    // Set when that key was unknown before this handshake, so a success must report it for pinning.
    bool host_key_learned_ = false;

    // Ephemeral X25519 keypair used for the SRP handshake. Created in sendClientHello, used in
    // readServerHello to derive the shared secret with the server's ephemeral public key, then
    // discarded. Not used for ANONYMOUS (which derives the secret immediately in sendClientHello).
    KeyPair key_pair_;

    BigNum N_;
    BigNum g_;
    BigNum s_;
    BigNum B_;
    BigNum a_;
    BigNum A_;

    Q_DISABLE_COPY_MOVE(ClientAuthenticator)
};

#endif // BASE_PEER_CLIENT_AUTHENTICATOR_H
