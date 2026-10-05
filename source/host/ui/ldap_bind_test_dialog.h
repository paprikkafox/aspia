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

#ifndef HOST_UI_LDAP_BIND_TEST_DIALOG_H
#define HOST_UI_LDAP_BIND_TEST_DIALOG_H

#include <QDialog>
#include <QString>

#include <memory>

#include "host/database.h"

class QAbstractButton;
class LdapDirectoryQuery;

namespace Ui {
class LdapBindTestDialog;
} // namespace Ui

//--------------------------------------------------------------------------------------------------
// Checks whether a login and a password bind against the directory, using the current LDAP
// settings. The login is first found with the user filter (under the service account, or
// anonymously when no bind DN is set) and then bound as that user, the same check the
// authenticator performs, but the result is shown to the operator instead of deciding access.
class LdapBindTestDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit LdapBindTestDialog(const Database::LdapConfig& config, QWidget* parent = nullptr);
    ~LdapBindTestDialog() final;

private slots:
    void onCheck();
    void onLoginChecked(bool success, int result_code, const QString& diagnostic,
                        const QString& user_dn);
    void onFailed(const QString& message);
    void onButtonBoxClicked(QAbstractButton* button);

private:
    std::unique_ptr<Ui::LdapBindTestDialog> ui;
    std::unique_ptr<LdapDirectoryQuery> query_;
    const Database::LdapConfig config_;

    Q_DISABLE_COPY_MOVE(LdapBindTestDialog)
};

#endif // HOST_UI_LDAP_BIND_TEST_DIALOG_H
