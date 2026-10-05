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

#include "host/ui/ldap_select_dialog.h"

#include <QAbstractButton>
#include <QDialogButtonBox>
#include <QHeaderView>
#include <QLineEdit>
#include <QPushButton>
#include <QTreeWidget>
#include <QTreeWidgetItem>

#include "base/logging.h"
#include "common/desktop/msg_box.h"
#include "host/ui/ui_ldap_select_dialog.h"

namespace {

// The value a row maps by: the login for a user, the group name for a group.
constexpr int kNameRole = Qt::UserRole + 1;

} // namespace

//--------------------------------------------------------------------------------------------------
LdapSelectDialog::LdapSelectDialog(
    LdapDirectoryQuery::Kind kind, const Database::LdapConfig& config, QWidget* parent)
    : QDialog(parent),
      ui(std::make_unique<Ui::LdapSelectDialog>()),
      query_(std::make_unique<LdapDirectoryQuery>()),
      kind_(kind)
{
    LOG(INFO) << "Ctor";
    ui->setupUi(this);

    if (kind_ == LdapDirectoryQuery::Kind::USER)
    {
        setWindowTitle(tr("Select User"));
        ui->tree_items->setHeaderLabels({ tr("Name"), tr("Login") });
    }
    else
    {
        setWindowTitle(tr("Select Group"));
        ui->tree_items->setHeaderLabels({ tr("Name"), tr("Description") });
    }

    ui->tree_items->header()->setStretchLastSection(true);

    connect(ui->edit_filter, &QLineEdit::textChanged, this, &LdapSelectDialog::onFilterChanged);
    connect(ui->tree_items, &QTreeWidget::itemSelectionChanged,
            this, &LdapSelectDialog::onSelectionChanged);
    connect(ui->tree_items, &QTreeWidget::itemDoubleClicked,
            this, &LdapSelectDialog::onItemDoubleClicked);
    connect(ui->button_box, &QDialogButtonBox::clicked,
            this, &LdapSelectDialog::onButtonBoxClicked);

    connect(query_.get(), &LdapDirectoryQuery::sig_entriesFound,
            this, &LdapSelectDialog::onEntriesFound);
    connect(query_.get(), &LdapDirectoryQuery::sig_failed, this, &LdapSelectDialog::onFailed);

    updateStatus();
    updateOkState();

    query_->search(config, kind_);
}

//--------------------------------------------------------------------------------------------------
LdapSelectDialog::~LdapSelectDialog()
{
    LOG(INFO) << "Dtor";
    query_->cancel();
}

//--------------------------------------------------------------------------------------------------
QString LdapSelectDialog::name() const
{
    QTreeWidgetItem* item = ui->tree_items->currentItem();
    return item ? item->data(0, kNameRole).toString() : QString();
}

//--------------------------------------------------------------------------------------------------
void LdapSelectDialog::onEntriesFound(const QVector<LdapDirectoryQuery::Entry>& entries)
{
    loaded_ = true;
    error_.clear();

    ui->tree_items->clear();

    for (const LdapDirectoryQuery::Entry& entry : entries)
    {
        auto* item = new QTreeWidgetItem(ui->tree_items);
        item->setText(0, entry.name);
        item->setText(1, kind_ == LdapDirectoryQuery::Kind::USER ? entry.login : entry.description);
        item->setData(0, kNameRole,
                      kind_ == LdapDirectoryQuery::Kind::USER ? entry.login : entry.name);
        item->setToolTip(0, entry.dn);
    }

    applyFilter();
    updateStatus();
    updateOkState();
}

//--------------------------------------------------------------------------------------------------
void LdapSelectDialog::onFailed(const QString& message)
{
    error_ = message;
    loaded_ = false;

    ui->tree_items->clear();

    updateStatus();
    updateOkState();
}

//--------------------------------------------------------------------------------------------------
void LdapSelectDialog::onFilterChanged(const QString& /* text */)
{
    applyFilter();
    updateStatus();
}

//--------------------------------------------------------------------------------------------------
void LdapSelectDialog::onSelectionChanged()
{
    updateOkState();
}

//--------------------------------------------------------------------------------------------------
void LdapSelectDialog::onItemDoubleClicked(QTreeWidgetItem* item, int /* column */)
{
    if (!item || item->isHidden())
        return;

    ui->tree_items->setCurrentItem(item);
    accept();
}

//--------------------------------------------------------------------------------------------------
void LdapSelectDialog::onButtonBoxClicked(QAbstractButton* button)
{
    if (ui->button_box->standardButton(button) != QDialogButtonBox::Ok)
    {
        reject();
        return;
    }

    if (!ui->tree_items->currentItem())
    {
        MsgBox::warning(this, tr("Select an entry from the list."));
        return;
    }

    accept();
}

//--------------------------------------------------------------------------------------------------
void LdapSelectDialog::applyFilter()
{
    const QString text = ui->edit_filter->text().trimmed();

    for (int i = 0; i < ui->tree_items->topLevelItemCount(); ++i)
    {
        QTreeWidgetItem* item = ui->tree_items->topLevelItem(i);
        const bool match = text.isEmpty() ||
            item->text(0).contains(text, Qt::CaseInsensitive) ||
            item->text(1).contains(text, Qt::CaseInsensitive);

        item->setHidden(!match);
    }

    // A row that the filter hid cannot be the choice.
    QTreeWidgetItem* current = ui->tree_items->currentItem();
    if (current && current->isHidden())
        ui->tree_items->setCurrentItem(nullptr);

    updateOkState();
}

//--------------------------------------------------------------------------------------------------
void LdapSelectDialog::updateStatus()
{
    if (!error_.isEmpty())
    {
        ui->label_status->setText(error_);
        return;
    }

    if (!loaded_)
    {
        ui->label_status->setText(tr("Loading..."));
        return;
    }

    const int total = ui->tree_items->topLevelItemCount();
    if (!total)
    {
        ui->label_status->setText(kind_ == LdapDirectoryQuery::Kind::USER
            ? tr("No users found.")
            : tr("No groups found."));
        return;
    }

    ui->label_status->setText(tr("Shown: %1 of %2").arg(visibleCount()).arg(total));
}

//--------------------------------------------------------------------------------------------------
void LdapSelectDialog::updateOkState()
{
    QPushButton* ok = ui->button_box->button(QDialogButtonBox::Ok);
    if (ok)
        ok->setEnabled(ui->tree_items->currentItem() != nullptr);
}

//--------------------------------------------------------------------------------------------------
int LdapSelectDialog::visibleCount() const
{
    int count = 0;

    for (int i = 0; i < ui->tree_items->topLevelItemCount(); ++i)
    {
        if (!ui->tree_items->topLevelItem(i)->isHidden())
            ++count;
    }

    return count;
}
