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

#include "host/ui/ldap_mapping_dialog.h"

#include <QAbstractButton>
#include <QDialogButtonBox>
#include <QLineEdit>
#include <QPushButton>
#include <QTreeWidget>
#include <QTreeWidgetItem>

#include "base/logging.h"
#include "base/peer/user.h"
#include "common/desktop/msg_box.h"
#include "common/desktop/session_type.h"
#include "host/ldap_directory_query.h"
#include "host/ui/ldap_select_dialog.h"
#include "host/ui/ui_ldap_mapping_dialog.h"
#include "proto/peer.h"

namespace {

// A group name is not a login: it can be long and may hold any character allowed in an RDN. The
// limit only keeps an unreasonable paste out of the settings.
constexpr int kMaxGroupNameLength = 1024;

} // namespace

//--------------------------------------------------------------------------------------------------
LdapMappingDialog::LdapMappingDialog(
    Kind kind, const QString& name, quint32 sessions, const Database::LdapConfig& config,
    QWidget* parent)
    : QDialog(parent),
      ui(std::make_unique<Ui::LdapMappingDialog>()),
      kind_(kind),
      config_(config)
{
    LOG(INFO) << "Ctor";
    ui->setupUi(this);

    if (kind_ == Kind::GROUP)
    {
        setWindowTitle(tr("Group Mapping"));
        ui->label_name->setText(tr("Group:"));
    }
    else
    {
        setWindowTitle(tr("User Mapping"));
        ui->label_name->setText(tr("User:"));
    }

    ui->edit_name->setText(name);

    auto add_session = [&](proto::peer::SessionType session_type)
    {
        auto* item = new QTreeWidgetItem();

        item->setText(0, sessionName(session_type));
        item->setIcon(0, sessionIcon(session_type));
        item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
        item->setData(0, Qt::UserRole, QVariant(session_type));
        item->setCheckState(0, (sessions & static_cast<quint32>(session_type)) ? Qt::Checked
                                                                              : Qt::Unchecked);

        ui->tree_sessions->addTopLevelItem(item);
    };

    add_session(proto::peer::SESSION_TYPE_DESKTOP);
    add_session(proto::peer::SESSION_TYPE_TERMINAL);
    add_session(proto::peer::SESSION_TYPE_FILE_TRANSFER);
    add_session(proto::peer::SESSION_TYPE_SYSTEM_INFO);
    add_session(proto::peer::SESSION_TYPE_CHAT);

    connect(ui->button_select, &QPushButton::clicked, this, &LdapMappingDialog::onSelectName);
    connect(ui->button_check_all, &QPushButton::clicked,
            this, &LdapMappingDialog::onCheckAllButtonPressed);
    connect(ui->button_check_none, &QPushButton::clicked,
            this, &LdapMappingDialog::onCheckNoneButtonPressed);
    connect(ui->button_box, &QDialogButtonBox::clicked, this, &LdapMappingDialog::onButtonBoxClicked);
}

//--------------------------------------------------------------------------------------------------
LdapMappingDialog::~LdapMappingDialog()
{
    LOG(INFO) << "Dtor";
}

//--------------------------------------------------------------------------------------------------
QString LdapMappingDialog::name() const
{
    return ui->edit_name->text().trimmed();
}

//--------------------------------------------------------------------------------------------------
quint32 LdapMappingDialog::sessions() const
{
    quint32 result = 0;

    for (int i = 0; i < ui->tree_sessions->topLevelItemCount(); ++i)
    {
        QTreeWidgetItem* item = ui->tree_sessions->topLevelItem(i);
        if (item->checkState(0) == Qt::Checked)
            result |= item->data(0, Qt::UserRole).toUInt();
    }

    return result;
}

//--------------------------------------------------------------------------------------------------
void LdapMappingDialog::onSelectName()
{
    LOG(INFO) << "[ACTION] Select the name for the mapping";

    LdapSelectDialog dialog(kind_ == Kind::GROUP ? LdapDirectoryQuery::Kind::GROUP
                                                 : LdapDirectoryQuery::Kind::USER,
                            config_, this);

    if (dialog.exec() != QDialog::Accepted)
        return;

    ui->edit_name->setText(dialog.name());
}

//--------------------------------------------------------------------------------------------------
void LdapMappingDialog::onCheckAllButtonPressed()
{
    LOG(INFO) << "[ACTION] Check all button pressed";

    for (int i = 0; i < ui->tree_sessions->topLevelItemCount(); ++i)
        ui->tree_sessions->topLevelItem(i)->setCheckState(0, Qt::Checked);
}

//--------------------------------------------------------------------------------------------------
void LdapMappingDialog::onCheckNoneButtonPressed()
{
    LOG(INFO) << "[ACTION] Check none button pressed";

    for (int i = 0; i < ui->tree_sessions->topLevelItemCount(); ++i)
        ui->tree_sessions->topLevelItem(i)->setCheckState(0, Qt::Unchecked);
}

//--------------------------------------------------------------------------------------------------
void LdapMappingDialog::onButtonBoxClicked(QAbstractButton* button)
{
    if (ui->button_box->standardButton(button) != QDialogButtonBox::Ok)
    {
        LOG(INFO) << "[ACTION] Rejected by user";
        reject();
        return;
    }

    LOG(INFO) << "[ACTION] Accepted by user";

    const QString name = ui->edit_name->text().trimmed();

    if (kind_ == Kind::GROUP)
    {
        if (name.isEmpty() || name.length() > kMaxGroupNameLength)
        {
            MsgBox::warning(this, tr("Enter the group name or choose it from the directory."));
            ui->edit_name->setFocus();
            return;
        }
    }
    else
    {
        if (name.isEmpty() ||
            name.length() > static_cast<qsizetype>(User::kMaxUserNameLength) ||
            !User::isValidLogin(name))
        {
            MsgBox::warning(this, tr("Enter the LDAP user name or choose it from the directory."));
            ui->edit_name->setFocus();
            return;
        }
    }

    accept();
}
