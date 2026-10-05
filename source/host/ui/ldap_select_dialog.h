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

#ifndef HOST_UI_LDAP_SELECT_DIALOG_H
#define HOST_UI_LDAP_SELECT_DIALOG_H

#include <QDialog>
#include <QString>
#include <QVector>

#include <memory>

#include "host/database.h"
#include "host/ldap_directory_query.h"

class QAbstractButton;
class QTreeWidgetItem;

namespace Ui {
class LdapSelectDialog;
} // namespace Ui

//--------------------------------------------------------------------------------------------------
// Picks one identity from the directory for a mapping: a user (its login) or a group (its name).
// The list is loaded asynchronously with the settings it is given; a filter box narrows it down as
// it is typed, filtering the list locally so typing does not query the directory again.
class LdapSelectDialog final : public QDialog
{
    Q_OBJECT

public:
    LdapSelectDialog(LdapDirectoryQuery::Kind kind, const Database::LdapConfig& config,
                     QWidget* parent = nullptr);
    ~LdapSelectDialog() final;

    // The value the mapping is written with: the login for a user, the group name for a group.
    [[nodiscard]] QString name() const;

private slots:
    void onEntriesFound(const QVector<LdapDirectoryQuery::Entry>& entries);
    void onFailed(const QString& message);
    void onFilterChanged(const QString& text);
    void onSelectionChanged();
    void onItemDoubleClicked(QTreeWidgetItem* item, int column);
    void onButtonBoxClicked(QAbstractButton* button);

private:
    void applyFilter();
    void updateStatus();
    void updateOkState();
    [[nodiscard]] int visibleCount() const;

    std::unique_ptr<Ui::LdapSelectDialog> ui;
    std::unique_ptr<LdapDirectoryQuery> query_;
    const LdapDirectoryQuery::Kind kind_;

    bool loaded_ = false;
    QString error_;

    Q_DISABLE_COPY_MOVE(LdapSelectDialog)
};

#endif // HOST_UI_LDAP_SELECT_DIALOG_H
