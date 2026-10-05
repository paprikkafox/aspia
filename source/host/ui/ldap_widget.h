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

#ifndef HOST_UI_LDAP_WIDGET_H
#define HOST_UI_LDAP_WIDGET_H

#include <QVector>
#include <QWidget>

#include <memory>

#include "host/database.h"

class QCheckBox;
class QTreeWidget;
class QTreeWidgetItem;

namespace Ui {
class LdapWidget;
} // namespace Ui

//--------------------------------------------------------------------------------------------------
// LDAP authentication settings as a page of the host settings: the connection, the service bind and
// the user search, the group and user mappings to the host permission bitmask, and the advanced
// policy. Mappings are edited like the local users list: a list of names, add, edit and delete
// buttons, a context menu, and a dialog per mapping for the rights, chosen on the session list of
// the user dialog.
class LdapWidget final : public QWidget
{
    Q_OBJECT

public:
    explicit LdapWidget(QWidget* parent = nullptr);
    ~LdapWidget() final;

    // reload() loads the settings from the database and save() writes them back. save() returns
    // false when the database refused the write; the caller reports the failure.
    void reload();
    [[nodiscard]] bool save();

signals:
    // Emitted when a control changes, so the settings dialog can enable its Apply button.
    void sig_changed();

private slots:
    void onTestConnection();
    void onCheckLogin();
    void onCaCertificate();
    void onAddGroup();
    void onModifyGroup();
    void onDeleteGroup();
    void onAddUser();
    void onModifyUser();
    void onDeleteUser();
    void onMappingsContextMenu(const QPoint& point);
    void onMappingsItemDoubleClicked(QTreeWidgetItem* item, int column);
    void onMappingsSelectionChanged();
    void onEnabledToggled(bool checked);

private:
    void markChanged();
    void updateCaCertificateButton();
    [[nodiscard]] Database::LdapConfig collectConfig() const;

    // These take the kind of mapping they work on, so the group and user tabs share them instead of
    // keeping two copies of the same code.
    [[nodiscard]] QTreeWidget* mappingTree(bool is_group) const;
    void reloadMappings(bool is_group);
    [[nodiscard]] QVector<Database::LdapMapping> collectMappings(bool is_group) const;
    void addMapping(bool is_group);
    void modifyMapping(bool is_group);
    void removeMapping(bool is_group);
    void updateButtonsState();

    std::unique_ptr<Ui::LdapWidget> ui;
    QVector<QCheckBox*> default_sessions_;

    // The certificate of the CA, PEM encoded, as last edited in its dialog.
    QString ca_certificate_;

    // Set while reload() fills the controls, so the changes it makes are not taken for user edits.
    bool loading_ = false;

    Q_DISABLE_COPY_MOVE(LdapWidget)
};

#endif // HOST_UI_LDAP_WIDGET_H
