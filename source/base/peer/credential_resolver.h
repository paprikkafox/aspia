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

#ifndef BASE_PEER_CREDENTIAL_RESOLVER_H
#define BASE_PEER_CREDENTIAL_RESOLVER_H

#include <QObject>
#include <QString>

class SecureString;

//--------------------------------------------------------------------------------------------------
// Resolves credentials sent over the IDENTIFY_PASSWORD path to the host permission bitmask. The
// resolution is asynchronous; the SRP path does not use a resolver, so the server creates one only
// when a capable client offers the password method.
class CredentialResolver : public QObject
{
    Q_OBJECT

public:
    explicit CredentialResolver(QObject* parent = nullptr)
        : QObject(parent)
    {
        // Nothing
    }

    ~CredentialResolver() override = default;

    // Starts the asynchronous validation of |login| with |password|.
    virtual void resolve(const QString& login, const SecureString& password) = 0;
    virtual void cancel() = 0;

signals:
    void sig_resolved(const QString& user_name, quint32 sessions);
    void sig_denied();
};

#endif // BASE_PEER_CREDENTIAL_RESOLVER_H
