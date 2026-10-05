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

#ifndef HOST_UI_LDAP_MAPPING_DIALOG_H
#define HOST_UI_LDAP_MAPPING_DIALOG_H

#include <QDialog>
#include <QString>

#include <memory>

#include "host/database.h"

class QAbstractButton;

namespace Ui {
class LdapMappingDialog;
} // namespace Ui

//--------------------------------------------------------------------------------------------------
// Edits one LDAP mapping: a group or a user, and the rights the mapping grants. The name can be
// typed by hand or chosen from the directory with a picker dialog; the rights are chosen on the
// same session list as the local user dialog.
class LdapMappingDialog final : public QDialog
{
    Q_OBJECT

public:
    enum class Kind
    {
        GROUP, // The name is a group name.
        USER   // The name is a login.
    };

    LdapMappingDialog(Kind kind, const QString& name, quint32 sessions,
                      const Database::LdapConfig& config, QWidget* parent = nullptr);
    ~LdapMappingDialog() final;

    [[nodiscard]] QString name() const;
    [[nodiscard]] quint32 sessions() const;

private slots:
    void onSelectName();
    void onCheckAllButtonPressed();
    void onCheckNoneButtonPressed();
    void onButtonBoxClicked(QAbstractButton* button);

private:
    std::unique_ptr<Ui::LdapMappingDialog> ui;
    const Kind kind_;
    const Database::LdapConfig config_;

    Q_DISABLE_COPY_MOVE(LdapMappingDialog)
};

#endif // HOST_UI_LDAP_MAPPING_DIALOG_H
