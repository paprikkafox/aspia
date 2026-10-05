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

#include "host/ui/ldap_bind_test_dialog.h"

#include <QAbstractButton>
#include <QDialogButtonBox>
#include <QLineEdit>
#include <QPushButton>

#include "base/logging.h"
#include "common/desktop/msg_box.h"
#include "common/desktop/password_edit.h"
#include "host/ldap_directory_query.h"
#include "host/ui/ui_ldap_bind_test_dialog.h"

//--------------------------------------------------------------------------------------------------
LdapBindTestDialog::LdapBindTestDialog(const Database::LdapConfig& config, QWidget* parent)
    : QDialog(parent),
      ui(std::make_unique<Ui::LdapBindTestDialog>()),
      query_(std::make_unique<LdapDirectoryQuery>()),
      config_(config)
{
    LOG(INFO) << "Ctor";
    ui->setupUi(this);

    connect(ui->button_check, &QPushButton::clicked, this, &LdapBindTestDialog::onCheck);
    connect(ui->button_box, &QDialogButtonBox::clicked,
            this, &LdapBindTestDialog::onButtonBoxClicked);
    connect(query_.get(), &LdapDirectoryQuery::sig_loginChecked,
            this, &LdapBindTestDialog::onLoginChecked);
    connect(query_.get(), &LdapDirectoryQuery::sig_failed, this, &LdapBindTestDialog::onFailed);
}

//--------------------------------------------------------------------------------------------------
LdapBindTestDialog::~LdapBindTestDialog()
{
    LOG(INFO) << "Dtor";
    query_->cancel();
}

//--------------------------------------------------------------------------------------------------
void LdapBindTestDialog::onCheck()
{
    const QString login = ui->edit_login->text().trimmed();
    if (login.isEmpty())
    {
        MsgBox::warning(this, tr("Enter the login to check."));
        ui->edit_login->setFocus();
        return;
    }

    LOG(INFO) << "[ACTION] Check the bind of" << login;

    ui->button_check->setEnabled(false);
    ui->label_result->setText(tr("Checking..."));

    query_->checkLogin(config_, login, ui->edit_password->password());
}

//--------------------------------------------------------------------------------------------------
void LdapBindTestDialog::onLoginChecked(
    bool success, int result_code, const QString& diagnostic, const QString& user_dn)
{
    ui->button_check->setEnabled(true);

    if (success)
    {
        ui->label_result->setText(user_dn.isEmpty()
            ? tr("The bind succeeded. The password is correct.")
            : tr("The bind succeeded (%1). The password is correct.").arg(user_dn));
        return;
    }

    if (result_code == LdapDirectoryQuery::kLoginNotFound)
    {
        ui->label_result->setText(tr("The login was not found in the directory."));
        return;
    }

    ui->label_result->setText(tr("The bind failed (code %1: %2).").arg(result_code).arg(diagnostic));
}

//--------------------------------------------------------------------------------------------------
void LdapBindTestDialog::onFailed(const QString& message)
{
    ui->button_check->setEnabled(true);
    ui->label_result->setText(message);
}

//--------------------------------------------------------------------------------------------------
void LdapBindTestDialog::onButtonBoxClicked(QAbstractButton* button)
{
    if (ui->button_box->standardButton(button) == QDialogButtonBox::Close)
    {
        LOG(INFO) << "[ACTION] Closed by user";
        reject();
    }
}
