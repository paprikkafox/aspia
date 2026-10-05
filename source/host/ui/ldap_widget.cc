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

#include "host/ui/ldap_widget.h"

#include <QAction>
#include <QComboBox>
#include <QCoreApplication>
#include <QEventLoop>
#include <QIcon>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QStringList>
#include <QTimer>
#include <QTreeWidget>
#include <QTreeWidgetItem>

#include "base/crypto/secure_byte_array.h"
#include "base/crypto/secure_string.h"
#include "base/ldap/ldap_connection.h"
#include "base/peer/user.h"
#include "base/time_types.h"
#include "common/desktop/msg_box.h"
#include "common/desktop/session_type.h"
#include "host/ldap_utils.h"
#include "host/ui/ca_certificate_dialog.h"
#include "host/ui/ldap_bind_test_dialog.h"
#include "host/ui/ldap_mapping_dialog.h"
#include "host/ui/ui_ldap_widget.h"
#include "proto/peer.h"

namespace {

constexpr int kSessionCount = 5;

const char kGroupIcon[] = ":/img/folder.svg";
const char kUserIcon[] = ":/img/user.svg";

//--------------------------------------------------------------------------------------------------
proto::peer::SessionType defaultSessionType(int index)
{
    switch (index)
    {
        case 0: return proto::peer::SESSION_TYPE_DESKTOP;
        case 1: return proto::peer::SESSION_TYPE_TERMINAL;
        case 2: return proto::peer::SESSION_TYPE_FILE_TRANSFER;
        case 3: return proto::peer::SESSION_TYPE_SYSTEM_INFO;
        default: return proto::peer::SESSION_TYPE_CHAT;
    }
}

//--------------------------------------------------------------------------------------------------
// The rights a row holds, as the names of the session types that are on. A row with no rights is a
// mapping that grants nothing.
QString rightsSummary(quint32 sessions)
{
    if (!sessions)
        return QCoreApplication::translate("LdapWidget", "No rights");

    QStringList names;

    for (int i = 0; i < kSessionCount; ++i)
    {
        const proto::peer::SessionType type = defaultSessionType(i);
        if (sessions & static_cast<quint32>(type))
            names.append(sessionName(type));
    }

    return names.join(QStringLiteral(", "));
}

//--------------------------------------------------------------------------------------------------
void fillMappingItem(QTreeWidgetItem* item, bool is_group, const QString& name, quint32 sessions)
{
    item->setText(0, name);
    item->setIcon(0, QIcon(is_group ? kGroupIcon : kUserIcon));
    item->setData(0, Qt::UserRole, QVariant(sessions));
    item->setToolTip(0, rightsSummary(sessions));
}

} // namespace

//--------------------------------------------------------------------------------------------------
LdapWidget::LdapWidget(QWidget* parent)
    : QWidget(parent),
      ui(std::make_unique<Ui::LdapWidget>())
{
    ui->setupUi(this);

    ui->combobox_security->addItem(tr("StartTLS"), static_cast<int>(Database::LdapSecurity::STARTTLS));
    ui->combobox_security->addItem(tr("LDAPS"), static_cast<int>(Database::LdapSecurity::LDAPS));
    ui->combobox_security->addItem(tr("None (not recommended)"),
                                   static_cast<int>(Database::LdapSecurity::PLAIN));

    default_sessions_ = { ui->checkbox_default_desktop,
                          ui->checkbox_default_terminal,
                          ui->checkbox_default_file_transfer,
                          ui->checkbox_default_system_info,
                          ui->checkbox_default_chat };

    for (QTreeWidget* tree : { ui->tree_groups, ui->tree_users })
    {
        connect(tree, &QTreeWidget::customContextMenuRequested,
                this, &LdapWidget::onMappingsContextMenu);
        connect(tree, &QTreeWidget::itemDoubleClicked,
                this, &LdapWidget::onMappingsItemDoubleClicked);
        connect(tree, &QTreeWidget::itemSelectionChanged,
                this, &LdapWidget::onMappingsSelectionChanged);
    }

    connect(ui->button_add_group, &QPushButton::clicked, this, &LdapWidget::onAddGroup);
    connect(ui->button_modify_group, &QPushButton::clicked, this, &LdapWidget::onModifyGroup);
    connect(ui->button_delete_group, &QPushButton::clicked, this, &LdapWidget::onDeleteGroup);
    connect(ui->button_add_user, &QPushButton::clicked, this, &LdapWidget::onAddUser);
    connect(ui->button_modify_user, &QPushButton::clicked, this, &LdapWidget::onModifyUser);
    connect(ui->button_delete_user, &QPushButton::clicked, this, &LdapWidget::onDeleteUser);
    connect(ui->button_test, &QPushButton::clicked, this, &LdapWidget::onTestConnection);
    connect(ui->button_check_login, &QPushButton::clicked, this, &LdapWidget::onCheckLogin);
    connect(ui->button_ca_certificate, &QPushButton::clicked, this, &LdapWidget::onCaCertificate);
    connect(ui->checkbox_enabled, &QCheckBox::toggled, this, &LdapWidget::onEnabledToggled);

    // Every control reports an edit, so the settings dialog can enable its Apply button.
    for (QLineEdit* edit : { ui->edit_server, ui->edit_bind_dn, ui->edit_base_dn,
                             ui->edit_user_filter, ui->edit_user_name_attribute,
                             ui->edit_group_base_dn, ui->edit_group_filter,
                             ui->edit_group_attribute })
    {
        connect(edit, &QLineEdit::textChanged, this, &LdapWidget::markChanged);
    }

    connect(ui->edit_bind_password, &QLineEdit::textChanged, this, &LdapWidget::markChanged);

    connect(ui->spinbox_port, QOverload<int>::of(&QSpinBox::valueChanged),
            this, &LdapWidget::markChanged);
    connect(ui->spinbox_cache_ttl, QOverload<int>::of(&QSpinBox::valueChanged),
            this, &LdapWidget::markChanged);
    connect(ui->combobox_security, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &LdapWidget::markChanged);

    for (QCheckBox* box : { ui->checkbox_verify_peer, ui->checkbox_group_nested,
                            ui->checkbox_deny_if_unmapped, ui->checkbox_allow_local_fallback })
    {
        connect(box, &QCheckBox::toggled, this, &LdapWidget::markChanged);
    }

    for (QCheckBox* box : std::as_const(default_sessions_))
        connect(box, &QCheckBox::toggled, this, &LdapWidget::markChanged);

    reload();
}

//--------------------------------------------------------------------------------------------------
LdapWidget::~LdapWidget() = default;

//--------------------------------------------------------------------------------------------------
void LdapWidget::reload()
{
    loading_ = true;

    Database& database = Database::instance();
    const Database::LdapConfig config = database.ldapConfig();

    ui->checkbox_enabled->setChecked(config.enabled);
    ui->edit_server->setText(config.server);
    ui->spinbox_port->setValue(config.port);

    for (int i = 0; i < ui->combobox_security->count(); ++i)
    {
        if (ui->combobox_security->itemData(i).toInt() == static_cast<int>(config.security))
        {
            ui->combobox_security->setCurrentIndex(i);
            break;
        }
    }

    ui->checkbox_verify_peer->setChecked(config.verify_peer);

    ca_certificate_ = config.ca_certificate;
    updateCaCertificateButton();

    ui->edit_bind_dn->setText(config.bind_dn);
    ui->edit_bind_password->setPassword(SecureString(config.bind_password));
    ui->edit_base_dn->setText(config.base_dn);
    ui->edit_user_filter->setText(config.user_filter);
    ui->edit_user_name_attribute->setText(config.user_name_attribute);

    ui->checkbox_group_nested->setChecked(config.group_nested);
    ui->edit_group_base_dn->setText(config.group_base_dn);
    ui->edit_group_filter->setText(config.group_filter);
    ui->edit_group_attribute->setText(config.group_attribute);

    for (int i = 0; i < kSessionCount; ++i)
    {
        default_sessions_.at(i)->setChecked(
            config.default_sessions & static_cast<quint32>(defaultSessionType(i)));
    }

    ui->checkbox_deny_if_unmapped->setChecked(config.deny_if_unmapped);
    ui->checkbox_allow_local_fallback->setChecked(config.allow_local_fallback);
    ui->spinbox_cache_ttl->setValue(config.cache_ttl);

    reloadMappings(/* is_group */ true);
    reloadMappings(/* is_group */ false);

    loading_ = false;

    ui->tab_widget->setEnabled(ui->checkbox_enabled->isChecked());
    updateButtonsState();
}

//--------------------------------------------------------------------------------------------------
bool LdapWidget::save()
{
    Database& database = Database::instance();

    return database.setLdapConfig(collectConfig()) &&
           database.replaceLdapGroups(collectMappings(/* is_group */ true)) &&
           database.replaceLdapUsers(collectMappings(/* is_group */ false));
}

//--------------------------------------------------------------------------------------------------
void LdapWidget::markChanged()
{
    if (!loading_)
        emit sig_changed();
}

//--------------------------------------------------------------------------------------------------
Database::LdapConfig LdapWidget::collectConfig() const
{
    Database::LdapConfig config;

    config.enabled = ui->checkbox_enabled->isChecked();
    config.server = ui->edit_server->text().trimmed();
    config.port = static_cast<quint16>(ui->spinbox_port->value());
    config.security = static_cast<Database::LdapSecurity>(
        ui->combobox_security->currentData().toInt());
    config.verify_peer = ui->checkbox_verify_peer->isChecked();
    config.ca_certificate = ca_certificate_;

    config.bind_dn = ui->edit_bind_dn->text().trimmed();
    config.bind_password = ui->edit_bind_password->password().toString();
    config.base_dn = ui->edit_base_dn->text().trimmed();
    config.user_filter = ui->edit_user_filter->text().trimmed();
    config.user_name_attribute = ui->edit_user_name_attribute->text().trimmed();

    config.group_nested = ui->checkbox_group_nested->isChecked();
    config.group_base_dn = ui->edit_group_base_dn->text().trimmed();
    config.group_filter = ui->edit_group_filter->text().trimmed();
    config.group_attribute = ui->edit_group_attribute->text().trimmed();

    quint32 default_sessions = 0;
    for (int i = 0; i < kSessionCount; ++i)
    {
        if (default_sessions_.at(i)->isChecked())
            default_sessions |= static_cast<quint32>(defaultSessionType(i));
    }

    config.default_sessions = default_sessions;
    config.deny_if_unmapped = ui->checkbox_deny_if_unmapped->isChecked();
    config.allow_local_fallback = ui->checkbox_allow_local_fallback->isChecked();
    config.cache_ttl = ui->spinbox_cache_ttl->value();

    return config;
}

//--------------------------------------------------------------------------------------------------
QTreeWidget* LdapWidget::mappingTree(bool is_group) const
{
    return is_group ? ui->tree_groups : ui->tree_users;
}

//--------------------------------------------------------------------------------------------------
void LdapWidget::reloadMappings(bool is_group)
{
    QTreeWidget* tree = mappingTree(is_group);
    tree->clear();

    Database& database = Database::instance();
    const QVector<Database::LdapMapping> mappings =
        is_group ? database.ldapGroups() : database.ldapUsers();

    for (const Database::LdapMapping& mapping : mappings)
    {
        auto* item = new QTreeWidgetItem(tree);
        fillMappingItem(item, is_group, mapping.name, mapping.sessions);
    }
}

//--------------------------------------------------------------------------------------------------
QVector<Database::LdapMapping> LdapWidget::collectMappings(bool is_group) const
{
    QTreeWidget* tree = mappingTree(is_group);

    QVector<Database::LdapMapping> mappings;

    for (int i = 0; i < tree->topLevelItemCount(); ++i)
    {
        QTreeWidgetItem* item = tree->topLevelItem(i);
        if (!item)
            continue;

        const QString name = item->text(0).trimmed();
        if (name.isEmpty())
            continue;

        Database::LdapMapping mapping;
        mapping.name = name;
        mapping.flags = User::ENABLED;
        mapping.sessions = item->data(0, Qt::UserRole).toUInt();

        mappings.append(mapping);
    }

    return mappings;
}

//--------------------------------------------------------------------------------------------------
void LdapWidget::addMapping(bool is_group)
{
    LdapMappingDialog dialog(
        is_group ? LdapMappingDialog::Kind::GROUP : LdapMappingDialog::Kind::USER,
        QString(), 0, collectConfig(), this);

    if (dialog.exec() != QDialog::Accepted)
        return;

    QTreeWidget* tree = mappingTree(is_group);

    auto* item = new QTreeWidgetItem(tree);
    fillMappingItem(item, is_group, dialog.name(), dialog.sessions());

    tree->setCurrentItem(item);
    updateButtonsState();

    markChanged();
}

//--------------------------------------------------------------------------------------------------
void LdapWidget::modifyMapping(bool is_group)
{
    QTreeWidget* tree = mappingTree(is_group);

    QTreeWidgetItem* item = tree->currentItem();
    if (!item)
        return;

    LdapMappingDialog dialog(
        is_group ? LdapMappingDialog::Kind::GROUP : LdapMappingDialog::Kind::USER,
        item->text(0), item->data(0, Qt::UserRole).toUInt(), collectConfig(), this);

    if (dialog.exec() != QDialog::Accepted)
        return;

    fillMappingItem(item, is_group, dialog.name(), dialog.sessions());
    markChanged();
}

//--------------------------------------------------------------------------------------------------
void LdapWidget::removeMapping(bool is_group)
{
    QTreeWidget* tree = mappingTree(is_group);

    QTreeWidgetItem* item = tree->currentItem();
    if (!item)
        return;

    if (MsgBox::question(this, tr("Are you sure you want to delete mapping \"%1\"?")
                             .arg(item->text(0))) != MsgBox::Yes)
    {
        return;
    }

    delete tree->takeTopLevelItem(tree->indexOfTopLevelItem(item));
    updateButtonsState();
    markChanged();
}

//--------------------------------------------------------------------------------------------------
void LdapWidget::updateButtonsState()
{
    const bool group_selected = ui->tree_groups->currentItem() != nullptr;
    const bool user_selected = ui->tree_users->currentItem() != nullptr;

    ui->button_modify_group->setEnabled(group_selected);
    ui->button_delete_group->setEnabled(group_selected);
    ui->button_modify_user->setEnabled(user_selected);
    ui->button_delete_user->setEnabled(user_selected);
}

//--------------------------------------------------------------------------------------------------
void LdapWidget::onAddGroup()
{
    addMapping(/* is_group */ true);
}

//--------------------------------------------------------------------------------------------------
void LdapWidget::onModifyGroup()
{
    modifyMapping(/* is_group */ true);
}

//--------------------------------------------------------------------------------------------------
void LdapWidget::onDeleteGroup()
{
    removeMapping(/* is_group */ true);
}

//--------------------------------------------------------------------------------------------------
void LdapWidget::onAddUser()
{
    addMapping(/* is_group */ false);
}

//--------------------------------------------------------------------------------------------------
void LdapWidget::onModifyUser()
{
    modifyMapping(/* is_group */ false);
}

//--------------------------------------------------------------------------------------------------
void LdapWidget::onDeleteUser()
{
    removeMapping(/* is_group */ false);
}

//--------------------------------------------------------------------------------------------------
void LdapWidget::onMappingsContextMenu(const QPoint& point)
{
    QTreeWidget* tree = qobject_cast<QTreeWidget*>(sender());
    if (!tree)
        return;

    const bool is_group = (tree == ui->tree_groups);

    tree->setCurrentItem(tree->itemAt(point));

    QMenu menu(this);
    QAction* add_action = menu.addAction(tr("Add"));
    QAction* modify_action = menu.addAction(tr("Edit"));
    QAction* delete_action = menu.addAction(tr("Delete"));

    modify_action->setEnabled(tree->currentItem() != nullptr);
    delete_action->setEnabled(tree->currentItem() != nullptr);

    QAction* chosen = menu.exec(tree->viewport()->mapToGlobal(point));
    if (chosen == add_action)
        addMapping(is_group);
    else if (chosen == modify_action)
        modifyMapping(is_group);
    else if (chosen == delete_action)
        removeMapping(is_group);
}

//--------------------------------------------------------------------------------------------------
void LdapWidget::onMappingsItemDoubleClicked(QTreeWidgetItem* /* item */, int /* column */)
{
    QTreeWidget* tree = qobject_cast<QTreeWidget*>(sender());
    if (!tree)
        return;

    modifyMapping(tree == ui->tree_groups);
}

//--------------------------------------------------------------------------------------------------
void LdapWidget::onMappingsSelectionChanged()
{
    updateButtonsState();
}

//--------------------------------------------------------------------------------------------------
void LdapWidget::onEnabledToggled(bool checked)
{
    ui->tab_widget->setEnabled(checked);
    markChanged();
}

//--------------------------------------------------------------------------------------------------
void LdapWidget::updateCaCertificateButton()
{
    // The certificate itself is not shown on the page, only whether one is set; it is a long text
    // that is read and edited in its own dialog.
    ui->button_ca_certificate->setText(ca_certificate_.isEmpty()
        ? tr("Not set")
        : tr("Set (%n characters)", "", ca_certificate_.size()));
}

//--------------------------------------------------------------------------------------------------
void LdapWidget::onCaCertificate()
{
    CaCertificateDialog dialog(ca_certificate_, this);
    if (dialog.exec() != QDialog::Accepted)
        return;

    ca_certificate_ = dialog.certificate();
    updateCaCertificateButton();

    markChanged();
}

//--------------------------------------------------------------------------------------------------
void LdapWidget::onTestConnection()
{
    const Database::LdapConfig config = collectConfig();
    if (config.server.isEmpty())
    {
        QMessageBox::warning(this, tr("LDAP Authentication"), tr("Enter the server address."));
        return;
    }

    LdapConnection connection;
    connection.setSecurity(toConnectionSecurity(config.security));
    connection.setOperationTimeout(MilliSeconds(10000));

    LdapConnection::TlsOptions tls_options;
    tls_options.verify_peer = config.verify_peer;
    tls_options.ca_certificate = config.ca_certificate;
    connection.setTlsOptions(tls_options);

    QEventLoop loop;
    QString result;

    connect(&connection, &LdapConnection::sig_connected, &loop, [&]()
    {
        connection.bind(config.bind_dn.toUtf8(), SecureByteArray(config.bind_password.toUtf8()));
    });
    connect(&connection, &LdapConnection::sig_bound, &loop,
            [&](bool success, int code, const QString& diagnostic)
    {
        if (success)
        {
            result = config.bind_dn.isEmpty() ? tr("The anonymous bind succeeded.")
                                              : tr("The service account bind succeeded.");
        }
        else
        {
            result = tr("The bind failed (code %1: %2).").arg(code).arg(diagnostic);
        }
        loop.quit();
    });
    connect(&connection, &LdapConnection::sig_errorOccurred, &loop,
            [&](LdapConnection::Error /* error */, const QString& text)
    {
        result = text;
        loop.quit();
    });

    QTimer::singleShot(10000, &loop, &QEventLoop::quit);

    connection.connectToHost(config.server, config.port);
    loop.exec();
    connection.close();

    if (result.isEmpty())
        result = tr("The connection timed out.");

    QMessageBox::information(this, tr("LDAP Authentication"), result);
}

//--------------------------------------------------------------------------------------------------
void LdapWidget::onCheckLogin()
{
    LdapBindTestDialog dialog(collectConfig(), this);
    dialog.exec();
}
