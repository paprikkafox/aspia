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

#include "host/ui/ca_certificate_dialog.h"

#include <QAbstractButton>
#include <QDialogButtonBox>
#include <QFile>
#include <QFileDialog>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSslCertificate>

#include "base/logging.h"
#include "common/desktop/msg_box.h"
#include "host/ui/ui_ca_certificate_dialog.h"

//--------------------------------------------------------------------------------------------------
CaCertificateDialog::CaCertificateDialog(const QString& certificate, QWidget* parent)
    : QDialog(parent),
      ui(std::make_unique<Ui::CaCertificateDialog>())
{
    LOG(INFO) << "Ctor";
    ui->setupUi(this);

    ui->edit_certificate->setPlainText(certificate);

    connect(ui->button_load, &QPushButton::clicked, this, &CaCertificateDialog::onLoadFromFile);
    connect(ui->button_box, &QDialogButtonBox::clicked, this, &CaCertificateDialog::onButtonBoxClicked);
}

//--------------------------------------------------------------------------------------------------
CaCertificateDialog::~CaCertificateDialog()
{
    LOG(INFO) << "Dtor";
}

//--------------------------------------------------------------------------------------------------
QString CaCertificateDialog::certificate() const
{
    return ui->edit_certificate->toPlainText().trimmed();
}

//--------------------------------------------------------------------------------------------------
void CaCertificateDialog::onLoadFromFile()
{
    LOG(INFO) << "[ACTION] Load certificate from a file";

    const QString file_path =
        QFileDialog::getOpenFileName(this, tr("Open"), QString(), tr("Certificate files (*.pem *.crt *.cer);;All files (*)"));

    if (file_path.isEmpty())
        return;

    QFile file(file_path);
    if (!file.open(QFile::ReadOnly))
    {
        LOG(ERROR) << "Unable to open" << file_path << ':' << file.errorString();
        MsgBox::warning(this, tr("Unable to open the file."));
        return;
    }

    // A PEM file written on Windows usually starts with a byte order mark, and a certificate parser
    // does not accept it.
    QByteArray data = file.readAll();
    if (data.startsWith("\xEF\xBB\xBF"))
        data.remove(0, 3);

    ui->edit_certificate->setPlainText(QString::fromUtf8(data).trimmed());
}

//--------------------------------------------------------------------------------------------------
void CaCertificateDialog::onButtonBoxClicked(QAbstractButton* button)
{
    if (ui->button_box->standardButton(button) != QDialogButtonBox::Ok)
    {
        LOG(INFO) << "[ACTION] Rejected by user";
        reject();
        return;
    }

    const QString text = certificate();

    // An empty box is valid and means the certificates the system trusts. Anything else must be a
    // certificate, so a wrong paste is caught here instead of at the first connection attempt.
    if (!text.isEmpty() && QSslCertificate::fromData(text.toUtf8(), QSsl::Pem).isEmpty())
    {
        LOG(ERROR) << "The text is not a PEM certificate";
        MsgBox::warning(this,
            tr("The text does not hold a certificate in PEM form. It begins with "
               "\"-----BEGIN CERTIFICATE-----\"."));
        ui->edit_certificate->setFocus();
        return;
    }

    LOG(INFO) << "[ACTION] Accepted by user";
    accept();
}
