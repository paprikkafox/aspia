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

#ifndef HOST_UI_CA_CERTIFICATE_DIALOG_H
#define HOST_UI_CA_CERTIFICATE_DIALOG_H

#include <QDialog>
#include <QString>

#include <memory>

class QAbstractButton;

namespace Ui {
class CaCertificateDialog;
} // namespace Ui

//--------------------------------------------------------------------------------------------------
// Edits the certificate authority the directory server is trusted through. The certificate is kept
// as the text of the PEM file, so it travels with the settings and the exported configuration
// instead of pointing at a path that only one machine has. An empty box means the certificates the
// system trusts.
class CaCertificateDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit CaCertificateDialog(const QString& certificate, QWidget* parent = nullptr);
    ~CaCertificateDialog() final;

    // The certificate as it was left in the box.
    [[nodiscard]] QString certificate() const;

private slots:
    void onLoadFromFile();
    void onButtonBoxClicked(QAbstractButton* button);

private:
    std::unique_ptr<Ui::CaCertificateDialog> ui;

    Q_DISABLE_COPY_MOVE(CaCertificateDialog)
};

#endif // HOST_UI_CA_CERTIFICATE_DIALOG_H
