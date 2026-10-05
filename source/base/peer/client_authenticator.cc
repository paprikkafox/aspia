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

#include "base/peer/client_authenticator.h"

#include <QSysInfo>

#include "base/location.h"
#include "base/logging.h"
#include "base/serialization.h"
#include "base/sys_info.h"
#include "base/version_constants.h"
#include "base/crypto/key_pair.h"
#include "base/crypto/random.h"
#include "base/crypto/secure_byte_array.h"
#include "base/crypto/srp_math.h"
#include "proto/key_exchange.h"

namespace {

const size_t kIvSize = 12; // 12 bytes.

//--------------------------------------------------------------------------------------------------
bool verifyNg(std::string_view N, std::string_view g)
{
    switch (N.size())
    {
        case 512: // 4096 bit
        {
            if (N != SrpMath::kNgPair_4096.first || g != SrpMath::kNgPair_4096.second)
                return false;
        }
        break;

        case 768: // 6144 bit
        {
            if (N != SrpMath::kNgPair_6144.first || g != SrpMath::kNgPair_6144.second)
                return false;
        }
        break;

        case 1024: // 8192 bit
        {
            if (N != SrpMath::kNgPair_8192.first || g != SrpMath::kNgPair_8192.second)
                return false;
        }
        break;

        // We do not allow groups less than 512 bytes (4096 bits).
        default:
            return false;
    }

    return true;
}

} // namespace

//--------------------------------------------------------------------------------------------------
ClientAuthenticator::ClientAuthenticator(QObject* parent)
    : Authenticator(Authenticator::Protocol::NG, parent)
{
    CLOG(TRACE) << "Ctor";
}

//--------------------------------------------------------------------------------------------------
ClientAuthenticator::~ClientAuthenticator()
{
    CLOG(TRACE) << "Dtor";
}

//--------------------------------------------------------------------------------------------------
void ClientAuthenticator::setPeerPublicKey(const QByteArray& public_key)
{
    CLOG(TRACE) << "Public key assigned:" << public_key.size();
    peer_public_key_ = public_key;
}

//--------------------------------------------------------------------------------------------------
void ClientAuthenticator::setIdentify(proto::key_exchange::Identify identify)
{
    CLOG(TRACE) << "Identify assigned:" << identify;
    identify_ = identify;
}

//--------------------------------------------------------------------------------------------------
void ClientAuthenticator::setPasswordAuth(PasswordAuth password_auth)
{
    password_auth_ = password_auth;
}

//--------------------------------------------------------------------------------------------------
void ClientAuthenticator::setUserName(const QString& username)
{
    CLOG(TRACE) << "User name assigned";
    username_ = username;
}

//--------------------------------------------------------------------------------------------------
void ClientAuthenticator::setPassword(const SecureString& password)
{
    CLOG(TRACE) << "Password assigned";
    password_ = password;
}

//--------------------------------------------------------------------------------------------------
void ClientAuthenticator::setSessionType(quint32 session_type)
{
    CLOG(TRACE) << "Session type assigned:" << session_type;
    session_type_ = session_type;
}

//--------------------------------------------------------------------------------------------------
void ClientAuthenticator::setDisplayName(const QString& display_name)
{
    CLOG(TRACE) << "Display name assigned:" << display_name;
    display_name_ = display_name;
}

//--------------------------------------------------------------------------------------------------
void ClientAuthenticator::setProbe(bool probe)
{
    CLOG(TRACE) << "Probe flag assigned:" << probe;
    is_probe_ = probe;
}

//--------------------------------------------------------------------------------------------------
bool ClientAuthenticator::onStarted()
{
    sendClientHello();
    return true;
}

//--------------------------------------------------------------------------------------------------
void ClientAuthenticator::onReceived(const QByteArray& buffer)
{
    switch (internal_state_)
    {
        case InternalState::READ_SERVER_HELLO:
        {
            if (readServerHello(buffer))
            {
                switch (identify_)
                {
                    case proto::key_exchange::IDENTIFY_ANONYMOUS:
                        internal_state_ = InternalState::READ_SESSION_CHALLENGE;
                        break;

                    case proto::key_exchange::IDENTIFY_SRP:
                        sendIdentify();
                        break;

                    case proto::key_exchange::IDENTIFY_PASSWORD:
                        sendPasswordIdentify();
                        break;

                    default:
                        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
                        break;
                }
            }
        }
        break;

        case InternalState::READ_SERVER_KEY_EXCHANGE:
        {
            if (readServerKeyExchange(buffer))
                sendClientKeyExchange();
        }
        break;

        case InternalState::READ_SESSION_CHALLENGE:
        {
            if (readSessionChallenge(buffer))
                sendSessionResponse();
        }
        break;

        default:
            finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
            return;
    }
}

//--------------------------------------------------------------------------------------------------
QByteArray ClientAuthenticator::keyLabel(Direction direction) const
{
    return direction == Direction::ENCRYPT ?
        QByteArrayLiteral("aspia/v1/c2s") : QByteArrayLiteral("aspia/v1/s2c");
}

//--------------------------------------------------------------------------------------------------
void ClientAuthenticator::sendClientHello()
{
    switch (identify_)
    {
        case proto::key_exchange::IDENTIFY_ANONYMOUS:
        case proto::key_exchange::IDENTIFY_SRP:
            break;

        default:
            finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
            return;
    }

    // Anonymous connections require a peer public key.
    if (identify_ == proto::key_exchange::IDENTIFY_ANONYMOUS && peer_public_key_.isEmpty())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return;
    }

    // SRP carries no out-of-band peer public key; the password method over a direct connection does.
    if (identify_ == proto::key_exchange::IDENTIFY_SRP && !peer_public_key_.isEmpty() &&
        password_auth_ != PasswordAuth::HOST_KEY)
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return;
    }

    proto::key_exchange::ClientHello client_hello;
    client_hello.set_encryption(proto::key_exchange::ENCRYPTION_AES256_GCM);
    client_hello.set_identify(identify_);

    // Offer the password method when configured. SRP stays the requested method so an older server
    // still works; a capable server may switch to the password method and answer in ServerHello.
    quint32 identify_methods = 1u << static_cast<quint32>(identify_);
    if (password_auth_ != PasswordAuth::DISABLE && identify_ == proto::key_exchange::IDENTIFY_SRP)
        identify_methods |= 1u << static_cast<quint32>(proto::key_exchange::IDENTIFY_PASSWORD);
    client_hello.set_identify_methods(identify_methods);

    encrypt_iv_ = Random::byteArray(kIvSize);
    if (encrypt_iv_.isEmpty())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return;
    }

    key_pair_ = KeyPair::create(KeyPair::Type::X25519);
    if (!key_pair_.isValid())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return;
    }

    QByteArray public_key = key_pair_.publicKey();
    if (public_key.isEmpty())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return;
    }

    client_hello.set_public_key(public_key.toStdString());
    client_hello.set_iv(encrypt_iv_.toStdString());

    // Remove this after support for versions below 3.0.0 ends.
    if (kMinimumSupportedVersion < kVersion_3_0_0)
    {
        proto::peer::Version* version = client_hello.mutable_version();
        version->set_major(ASPIA_VERSION_MAJOR);
        version->set_minor(ASPIA_VERSION_MINOR);
        version->set_patch(ASPIA_VERSION_PATCH);
    }

    QByteArray message = serialize(client_hello);
    if (message.isEmpty())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return;
    }

    // The transcript is assembled in readServerHello, once the selected method (and therefore the
    // position of the shared secret relative to ClientHello) is known.
    client_hello_ = message;

    CLOG(TRACE) << "Sending: ClientHello (" << message.size() << ")";
    emit sig_outgoingMessage(message, false);
    internal_state_ = InternalState::READ_SERVER_HELLO;
}

//--------------------------------------------------------------------------------------------------
bool ClientAuthenticator::readServerHello(const QByteArray& buffer)
{
    CLOG(TRACE) << "Received: ServerHello (" << buffer.size() << ")";

    if (buffer.isEmpty())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return false;
    }

    proto::key_exchange::ServerHello server_hello;
    if (!parse(buffer, &server_hello))
    {
        finish(FROM_HERE, ErrorCode::PROTOCOL_ERROR);
        return false;
    }

    CLOG(TRACE) << "Encryption:" << server_hello.encryption();

    encryption_ = server_hello.encryption();
    switch (encryption_)
    {
        case proto::key_exchange::ENCRYPTION_AES256_GCM:
            break;

        default:
            finish(FROM_HERE, ErrorCode::PROTOCOL_ERROR);
            return false;
    }

    // Both modes require ServerHello.iv (server's ephemeral or final IV for the upcoming
    // encryption). SRP additionally requires server's ephemeral public_key. ANONYMOUS never
    // carries server public_key in SH (server's long-term key is pre-shared).
    decrypt_iv_ = QByteArray::fromStdString(server_hello.iv());
    if (decrypt_iv_.isEmpty())
    {
        finish(FROM_HERE, ErrorCode::PROTOCOL_ERROR);
        return false;
    }

    // The server may select a method other than the one requested. An older server does not send the
    // field at all (its value stays SRP), so the requested method stands in that case.
    proto::key_exchange::Identify selected = server_hello.identify();
    if (selected == proto::key_exchange::IDENTIFY_SRP &&
        identify_ != proto::key_exchange::IDENTIFY_SRP)
    {
        selected = identify_;
    }
    identify_ = selected;

    // For anonymous and for the password method over a direct connection the host is authenticated
    // by its long-term key, which the client already knows: the server sends no key in ServerHello
    // and the shared secret comes from that key. Otherwise (SRP and the password method over a
    // brokered transport) the shared secret comes from the server's ephemeral key in ServerHello.
    const QByteArray server_public_key = QByteArray::fromStdString(server_hello.public_key());

    const bool uses_host_key =
        identify_ == proto::key_exchange::IDENTIFY_ANONYMOUS ||
        (identify_ == proto::key_exchange::IDENTIFY_PASSWORD &&
         password_auth_ == PasswordAuth::HOST_KEY);

    if (!key_pair_.isValid())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return false;
    }

    SecureByteArray x25519_secret;

    if (uses_host_key)
    {
        // The host key is either pinned/provisioned, or taken from ServerHello on first use (TOFU).
        QByteArray host_key = peer_public_key_;
        if (host_key.isEmpty())
        {
            host_key = server_public_key;
            if (host_key.isEmpty())
            {
                finish(FROM_HERE, ErrorCode::PROTOCOL_ERROR);
                return false;
            }
        }
        else if (!server_public_key.isEmpty() && server_public_key != host_key)
        {
            // The host presented a key different from the pinned one.
            finish(FROM_HERE, ErrorCode::ACCESS_DENIED);
            return false;
        }

        host_public_key_ = host_key;

        // The key was not known before this connection: it is pinned if the handshake succeeds.
        host_key_learned_ = identify_ == proto::key_exchange::IDENTIFY_PASSWORD &&
                            password_auth_ == PasswordAuth::HOST_KEY &&
                            peer_public_key_.isEmpty();

        x25519_secret = key_pair_.sessionKey(host_key);
        if (x25519_secret.isEmpty())
        {
            finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
            return false;
        }

        // Order: x25519_secret || ClientHello || ServerHello.
        appendTranscript(x25519_secret.toByteArray());
        appendTranscript(client_hello_);
    }
    else
    {
        if (server_public_key.isEmpty())
        {
            finish(FROM_HERE, ErrorCode::PROTOCOL_ERROR);
            return false;
        }

        // Order: ClientHello || x25519_secret || ServerHello.
        appendTranscript(client_hello_);

        x25519_secret = key_pair_.sessionKey(server_public_key);
        if (x25519_secret.isEmpty())
        {
            finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
            return false;
        }

        appendTranscript(x25519_secret.toByteArray());
    }

    // No further use of the keypair.
    key_pair_ = KeyPair();

    appendTranscript(buffer);

    // The session key derived from the transcript protects all subsequent handshake messages.
    CLOG(TRACE) << "Session key is ready";
    setSessionKeyReady();

    return true;
}

//--------------------------------------------------------------------------------------------------
void ClientAuthenticator::sendIdentify()
{
    if (username_.isEmpty())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return;
    }

    proto::key_exchange::SrpIdentify identify;
    identify.set_username(username_.toStdString());

    QByteArray message = serialize(identify);
    if (message.isEmpty())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return;
    }

    CLOG(TRACE) << "Sending: Identify (" << message.size() << ")";
    appendTranscript(message);

    emit sig_outgoingMessage(message, true);
    internal_state_ = InternalState::READ_SERVER_KEY_EXCHANGE;
}

//--------------------------------------------------------------------------------------------------
void ClientAuthenticator::sendPasswordIdentify()
{
    if (username_.isEmpty())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return;
    }

    proto::key_exchange::PasswordIdentify identify;
    identify.set_username(username_.toStdString());
    identify.set_password(password_.toString().toStdString());

    QByteArray message = serialize(identify);
    if (message.isEmpty())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return;
    }

    CLOG(TRACE) << "Sending: PasswordIdentify (" << message.size() << ")";

    // Encrypted under the handshake key established at ServerHello. The message is then bound into
    // the transcript, so the next key change moves both peers to the final session key.
    appendTranscript(message);
    emit sig_outgoingMessage(message, true);
    setSessionKeyReady();

    internal_state_ = InternalState::READ_SESSION_CHALLENGE;
}

//--------------------------------------------------------------------------------------------------
bool ClientAuthenticator::readServerKeyExchange(const QByteArray& buffer)
{
    CLOG(TRACE) << "Received: ServerKeyExchange (" << buffer.size() << ")";

    if (buffer.isEmpty())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return false;
    }

    appendTranscript(buffer);

    proto::key_exchange::SrpServerKeyExchange server_key_exchange;
    if (!parse(buffer, &server_key_exchange))
    {
        finish(FROM_HERE, ErrorCode::PROTOCOL_ERROR);
        return false;
    }

    if (server_key_exchange.salt().empty() || server_key_exchange.b().empty())
    {
        CLOG(ERROR) << "Salt size:" << server_key_exchange.salt().size();
        CLOG(ERROR) << "B size:" << server_key_exchange.b().size();

        finish(FROM_HERE, ErrorCode::PROTOCOL_ERROR);
        return false;
    }

    if (!verifyNg(server_key_exchange.number(), server_key_exchange.generator()))
    {
        finish(FROM_HERE, ErrorCode::PROTOCOL_ERROR);
        return false;
    }

    N_ = BigNum::fromStdString(server_key_exchange.number());
    if (!N_.isValid())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return false;
    }

    g_ = BigNum::fromStdString(server_key_exchange.generator());
    if (!g_.isValid())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return false;
    }

    s_ = BigNum::fromStdString(server_key_exchange.salt());
    if (!s_.isValid())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return false;
    }

    B_ = BigNum::fromStdString(server_key_exchange.b());
    if (!B_.isValid())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return false;
    }

    decrypt_iv_ = QByteArray::fromStdString(server_key_exchange.iv());
    if (decrypt_iv_.isEmpty())
    {
        finish(FROM_HERE, ErrorCode::PROTOCOL_ERROR);
        return false;
    }

    a_ = BigNum::fromByteArray(Random::byteArray(128)); // 1024 bits.
    if (!a_.isValid())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return false;
    }

    A_ = SrpMath::calc_A(a_, N_, g_);
    if (!A_.isValid())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return false;
    }

    encrypt_iv_ = Random::byteArray(kIvSize);
    if (encrypt_iv_.isEmpty())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return false;
    }

    if (!SrpMath::verify_B_mod_N(B_, N_))
    {
        finish(FROM_HERE, ErrorCode::PROTOCOL_ERROR);
        return false;
    }

    // SRP key computation is deferred to sendClientKeyExchange so that on both sides the
    // transcript hash absorbs ClientKeyExchange before the SRP key is mixed in.
    return true;
}

//--------------------------------------------------------------------------------------------------
void ClientAuthenticator::sendClientKeyExchange()
{
    if (encrypt_iv_.isEmpty() || !A_.isValid() || !B_.isValid() || !N_.isValid() || !g_.isValid() || !a_.isValid())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return;
    }

    BigNum u = SrpMath::calc_u(A_, B_, N_);
    if (!u.isValid())
    {
        finish(FROM_HERE, ErrorCode::PROTOCOL_ERROR);
        return;
    }

    BigNum x = SrpMath::calc_x(s_, username_, password_);
    if (!x.isValid())
    {
        finish(FROM_HERE, ErrorCode::PROTOCOL_ERROR);
        return;
    }

    BigNum key = SrpMath::calcClientKey(N_, B_, g_, x, a_, u);
    if (!key.isValid())
    {
        finish(FROM_HERE, ErrorCode::PROTOCOL_ERROR);
        return;
    }

    proto::key_exchange::SrpClientKeyExchange client_key_exchange;
    client_key_exchange.set_a(A_.toStdString());
    client_key_exchange.set_iv(encrypt_iv_.toStdString());

    QByteArray message = serialize(client_key_exchange);
    if (message.isEmpty())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return;
    }

    CLOG(TRACE) << "Sending: ClientKeyExchange (" << message.size() << ")";
    appendTranscript(message);

    // Still encrypted under the ephemeral key (channel rebuilds the encryptor on the next
    // sig_keyChanged after this message is queued and encrypted).
    emit sig_outgoingMessage(message, true);
    internal_state_ = InternalState::READ_SESSION_CHALLENGE;

    // The SRP key is mixed in after SrpClientKeyExchange, so the transcript covers the full
    // handshake plus the SRP key, and sessionKey() then returns the final key used for
    // SessionChallenge and SessionResponse.
    SecureByteArray srp_raw_key(key.toByteArray());
    if (srp_raw_key.isEmpty())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return;
    }

    appendTranscript(srp_raw_key.toByteArray());

    CLOG(TRACE) << "Session key is ready";
    setSessionKeyReady();
}

//--------------------------------------------------------------------------------------------------
bool ClientAuthenticator::readSessionChallenge(const QByteArray& buffer)
{
    CLOG(TRACE) << "Received: SessionChallenge (" << buffer.size() << ")";

    if (buffer.isEmpty())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return false;
    }

    proto::key_exchange::SessionChallenge challenge;
    if (!parse(buffer, &challenge))
    {
        finish(FROM_HERE, ErrorCode::PROTOCOL_ERROR);
        return false;
    }

    if (!(challenge.session_types() & session_type_))
    {
        finish(FROM_HERE, ErrorCode::SESSION_DENIED);
        return false;
    }

    if (!setPeerOsName(challenge.os_name()) ||
        !setPeerComputerName(challenge.computer_name()) ||
        !setPeerArch(challenge.arch()) ||
        !setPeerDisplayName(challenge.display_name()) ||
        !setPeerVersion(challenge.version()))
    {
        finish(FROM_HERE, ErrorCode::PROTOCOL_ERROR);
        return false;
    }

    CLOG(TRACE) << "Server (version:" << peerVersion().toString() << "name:" << peerComputerName()
                << "os:" << peerOsName() << "cores:" << challenge.cpu_cores()
                << "arch:" << peerArch() << "display_name:" << peerDisplayName() << ")";

    if (peerVersion() < kMinimumSupportedVersion)
    {
        finish(FROM_HERE, ErrorCode::VERSION_ERROR);
        return false;
    }

    return true;
}

//--------------------------------------------------------------------------------------------------
void ClientAuthenticator::sendSessionResponse()
{
    proto::key_exchange::SessionResponse response;
    response.set_session_type(session_type_);

    proto::peer::Version* version = response.mutable_version();
    version->set_major(ASPIA_VERSION_MAJOR);
    version->set_minor(ASPIA_VERSION_MINOR);
    version->set_patch(ASPIA_VERSION_PATCH);
    version->set_revision(GIT_COMMIT_COUNT);

    response.set_os_name(SysInfo::operatingSystemName().toStdString());
    response.set_computer_name(SysInfo::computerName().toStdString());
    response.set_cpu_cores(static_cast<quint32>(SysInfo::processorThreads()));
    response.set_display_name(display_name_.toStdString());
    response.set_arch(QSysInfo::buildCpuArchitecture().toStdString());
    response.set_probe(is_probe_);

    QByteArray message = serialize(response);
    if (message.isEmpty())
    {
        finish(FROM_HERE, ErrorCode::UNKNOWN_ERROR);
        return;
    }

    CLOG(TRACE) << "Sending: SessionResponse (" << message.size() << ")";
    emit sig_outgoingMessage(message, true);

    // The host accepted this session, so a key that was pinned tentatively on first use is confirmed.
    if (host_key_learned_)
        emit sig_hostKeyLearned(host_public_key_);

    finish(FROM_HERE, ErrorCode::SUCCESS);
}
