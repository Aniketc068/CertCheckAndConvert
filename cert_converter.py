import sys
import traceback
import requests
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QFileDialog,
    QVBoxLayout, QMessageBox, QInputDialog, QLineEdit, QFrame, QHBoxLayout
)
import os
import ctypes
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
import qdarkstyle
import base64
from PyQt5.QtGui import QIcon, QPixmap
from io import BytesIO
from image import logo_png  # Assuming it's in image.py
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.ocsp import OCSPRequestBuilder, OCSPResponseStatus
from PyQt5.QtCore import QSharedMemory, QTimer

class SingleInstanceApp(QApplication):
    def __init__(self, *args):
        super(SingleInstanceApp, self).__init__(*args)
        self.shared_memory = QSharedMemory("CertCRCMtx")
        if not self.shared_memory.create(1):
            QMessageBox.critical(None, "Application Running",
                                 "This application is already running.\nPlease check the Task Manager and close any existing instance.")
            sys.exit(0)

class CertConverter(QWidget):

    def __init__(self):
        super().__init__()
        # Set window icon from base64 logo
        logo_bytes = base64.b64decode(logo_png)
        pixmap = QPixmap()
        pixmap.loadFromData(logo_bytes)
        self.setWindowIcon(QIcon(pixmap))

        self.setWindowTitle("Certificate Converter & Revocation Checker")
        self.setGeometry(500, 200, 650, 420)
        self.setFixedSize(650, 420)
        self.setStyleSheet("""
            QPushButton {
                font-size: 15px;
                font-weight: bold;
                padding: 14px;
                border-radius: 10px;
                background-color: #444;
            }
            QPushButton:hover {
                background-color: #555;
            }
            QLabel#titleLabel {
                font-size: 22px;
                font-weight: bold;
                color: white;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1e3c72, stop:1 #2a5298);
                padding: 20px;
                border-radius: 12px;
            }
        """)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        layout.addWidget(line)

        self.button_cer = QPushButton("📄 Convert .cer to .pem")
        self.button_cer.clicked.connect(self.convert_cer_to_pem)
        layout.addWidget(self.button_cer)

        self.button_pfx = QPushButton("🔐 Convert .pfx to certificate.pem & private_key.pem")
        self.button_pfx.clicked.connect(self.convert_pfx_to_pem)
        layout.addWidget(self.button_pfx)

        self.button_crl = QPushButton("🔍 Check Certificate CRL Status (.cer or .pfx)")
        self.button_crl.clicked.connect(self.check_crl_status)
        layout.addWidget(self.button_crl)

        self.button_ocsp = QPushButton("🔎 Check Certificate OCSP Status (.cer or .pfx)")
        self.button_ocsp.clicked.connect(self.check_ocsp_status)
        layout.addWidget(self.button_ocsp)
        

       # Add a thin horizontal line (light color) just above footer
        footer_separator = QFrame()
        footer_separator.setFrameShape(QFrame.HLine)
        footer_separator.setFrameShadow(QFrame.Plain)
        footer_separator.setStyleSheet("color: #FFFFFF;")  # Light gray line
        footer_separator.setFixedHeight(1)  # thin line
        layout.addWidget(footer_separator)

        # Footer: Left and Right aligned labels
        footer_layout = QHBoxLayout()
        footer_layout.setContentsMargins(0, 10, 0, 0)  # some top padding

        footer_left = QLabel()
        footer_left.setText(
            '<a href="https://github.com/Aniketc068" style="text-decoration: none; color: white;">'
            'Made with <span style="color: red;">❤️</span> by Aniket Chaturvedi</a>'
        )
        footer_left.setOpenExternalLinks(True)
        footer_left.setTextFormat(Qt.RichText)
        footer_left.setTextInteractionFlags(Qt.TextBrowserInteraction)
        footer_left.setCursor(Qt.PointingHandCursor)  # Changes cursor to hand on hover
        footer_left.setStyleSheet("font-size: 12px;")
        footer_left.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        footer_right = QLabel("v1.0")
        footer_right.setText(
            '<a href="https://github.com/Aniketc068" style="text-decoration: none; color: white;">'
            'v1.0</a>'
        )
        footer_right.setOpenExternalLinks(True)
        footer_right.setTextFormat(Qt.RichText)
        footer_right.setTextInteractionFlags(Qt.TextBrowserInteraction)
        footer_right.setCursor(Qt.PointingHandCursor)  # Changes cursor to hand on hover
        footer_right.setStyleSheet("font-size: 12px;")
        footer_right.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        footer_layout.addWidget(footer_left)
        footer_layout.addWidget(footer_right)

        footer_widget = QWidget()
        footer_widget.setLayout(footer_layout)

        layout.addWidget(footer_widget)

        self.setLayout(layout)

    def load_certificate_flexible(self, data):
        # Try PEM first, then DER
        loaders = [x509.load_pem_x509_certificate, x509.load_der_x509_certificate]
        for loader in loaders:
            try:
                cert = loader(data, default_backend())
                print(f"[INFO] Loaded certificate with {loader.__name__}")
                return cert
            except Exception:
                continue
        raise Exception("Failed to load certificate as PEM or DER format.")

    def convert_cer_to_pem(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select .cer File", "", "Certificate Files (*.cer *.crt *.pem *.pfx *.p12)")
        if file_path:
            try:
                with open(file_path, 'rb') as cer_file:
                    cer_data = cer_file.read()

                cert = self.load_certificate_flexible(cer_data)

                pem_data = cert.public_bytes(encoding=serialization.Encoding.PEM)
                pem_path = file_path.rsplit('.', 1)[0] + "_converted.pem"

                with open(pem_path, 'wb') as pem_file:
                    pem_file.write(pem_data)

                print(f"[SUCCESS] PEM written to: {pem_path}")
                QMessageBox.information(self, "Success", f"Converted to PEM:\n{pem_path}")

            except Exception as e:
                print("[ERROR] CER to PEM failed:")
                traceback.print_exc()
                QMessageBox.critical(self, "Error", f"Failed to convert:\n{str(e)}")

    def convert_pfx_to_pem(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select .pfx File", "", "PFX Files (*.pfx *.p12)")
        if not file_path:
            return

        print(f"[INFO] Reading .pfx: {file_path}")
        try:
            with open(file_path, 'rb') as pfx_file:
                pfx_data = pfx_file.read()

            while True:
                password, ok = QInputDialog.getText(
                    self, "Enter PFX Password", "Password:", QLineEdit.Password
                )
                if not ok:
                    return

                try:
                    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                        pfx_data,
                        password.encode() if password else None,
                        backend=default_backend()
                    )
                    break  # Password correct, exit loop
                except Exception:
                    QMessageBox.warning(self, "Incorrect Password", "Incorrect password. Please try again.")

            base_path = file_path.rsplit('.', 1)[0]

            if private_key:
                key_path = base_path + "_private_key.pem"
                with open(key_path, 'wb') as key_file:
                    key_file.write(private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                print(f"[SUCCESS] Private key saved: {key_path}")
            else:
                key_path = "(None)"

            if certificate:
                cert_path = base_path + "_certificate.pem"
                with open(cert_path, 'wb') as cert_file:
                    cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))
                print(f"[SUCCESS] Certificate saved: {cert_path}")
            else:
                cert_path = "(None)"

            QMessageBox.information(self, "Success", f"Saved:\n{cert_path}\n{key_path}")

        except Exception as e:
            print("[ERROR] PFX to PEM failed:")
            traceback.print_exc()
            QMessageBox.critical(self, "Error", f"Failed to convert:\n{str(e)}")


    def load_certificate(self, file_path):
        """
        Load certificate from .cer/.pem/.crt or .pfx/.p12 file.
        Returns (x509.Certificate, additional_certs or None)
        """
        ext = os.path.splitext(file_path)[1].lower()

        if ext in [".pfx", ".p12"]:
            # Prompt password for PFX
            while True:
                password, ok = QInputDialog.getText(
                    self, "Enter PFX Password", "Password:", QLineEdit.Password
                )
                if not ok:
                    return None, None

                try:
                    with open(file_path, 'rb') as f:
                        pfx_data = f.read()

                    private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
                        pfx_data,
                        password.encode() if password else None,
                        backend=default_backend()
                    )

                    if certificate is None:
                        QMessageBox.warning(self, "No Certificate", "No certificate found in the PFX file.")
                        return None, None

                    print("[INFO] Loaded certificate from PFX")
                    return certificate, additional_certs

                except Exception:
                    QMessageBox.warning(self, "Incorrect Password", "Incorrect password. Please try again.")
        else:
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()

                try:
                    cert = x509.load_der_x509_certificate(data, default_backend())
                    print("[INFO] Loaded DER certificate")
                except Exception:
                    cert = x509.load_pem_x509_certificate(data, default_backend())
                    print("[INFO] Loaded PEM certificate")

                return cert, None

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load certificate:\n{str(e)}")
                return None, None


    def get_root_cert_fingerprint(self, cert, additional_certs):
        # Check if cert itself is self-signed (root)
        def is_self_signed(c):
            return c.issuer == c.subject

        root_cert = None

        # 1) Check additional certs for self-signed root
        if additional_certs:
            for c in additional_certs:
                if is_self_signed(c):
                    root_cert = c
                    break

        # 2) If not found, check if cert is self-signed
        if root_cert is None:
            if is_self_signed(cert):
                root_cert = cert

        # 3) If still no root_cert, fallback to cert itself (leaf)
        if root_cert is None:
            root_cert = cert

        fingerprint = root_cert.fingerprint(hashes.SHA1())
        return fingerprint.hex()

    def check_crl_status(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Certificate or PFX File",
            "",
            "Certificate Files (*.cer *.crt *.pem *.pfx *.p12)"
        )
        if not file_path:
            return

        try:
            cert, additional_certs = self.load_certificate(file_path)
            if cert is None:
                return

    
            # Extract CRL Distribution Point URL
            try:
                crl_dp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
                # Some certs have multiple CRL distribution points - pick first full_name url
                crl_url = None
                for dp in crl_dp.value:
                    if dp.full_name:
                        for name in dp.full_name:
                            if hasattr(name, "value"):
                                crl_url = name.value
                                break
                    if crl_url:
                        break

                if not crl_url:
                    QMessageBox.warning(self, "No CRL URL", "No CRL Distribution Point URL found in the certificate.")
                    return

                print(f"[INFO] Found CRL URL: {crl_url}")
            except ExtensionNotFound:
                QMessageBox.warning(self, "No CRL Found", "The certificate has no CRL Distribution Point extension.")
                return

            # Download CRL
            response = requests.get(crl_url, timeout=10)
            if response.status_code != 200:
                raise Exception(f"Failed to fetch CRL: HTTP {response.status_code}")

            crl_data = response.content
            try:
                crl = x509.load_der_x509_crl(crl_data, default_backend())
            except ValueError:
                crl = x509.load_pem_x509_crl(crl_data, default_backend())
            serial = cert.serial_number
            revoked = crl.get_revoked_certificate_by_serial_number(serial)

            if revoked:
                msg = f"❌ The certificate IS REVOKED.\nSerial: {serial:X}"
            else:
                msg = f"✅ The certificate is NOT revoked.\nSerial: {serial:X}"

            QMessageBox.information(self, "CRL Check Result", msg)

        except Exception as e:
            print("[ERROR] CRL Check failed:")
            traceback.print_exc()
            QMessageBox.critical(self, "CRL Check Failed", f"An error occurred:\n{str(e)}")

    def check_ocsp_status(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Certificate or PFX File",
            "",
            "Certificate Files (*.cer *.crt *.pem *.pfx *.p12)"
        )
        if not file_path:
            return

        try:
            cert, additional_certs = self.load_certificate(file_path)
            if cert is None:
                return

            # Extract OCSP URL and Issuer cert URL from AIA extension
            try:
                aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
                ocsp_urls = [desc.access_location.value for desc in aia.value if desc.access_method == x509.AuthorityInformationAccessOID.OCSP]
                issuer_urls = [desc.access_location.value for desc in aia.value if desc.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS]

                if not ocsp_urls:
                    QMessageBox.warning(self, "No OCSP URL", "No OCSP URL found in certificate's Authority Information Access extension.")
                    return
                ocsp_url = ocsp_urls[0]
                print(f"[INFO] Found OCSP URL: {ocsp_url}")

                if not issuer_urls:
                    QMessageBox.warning(self, "No Issuer Cert URL", "No Issuer certificate URL found in certificate's Authority Information Access extension.")
                    return
                issuer_url = issuer_urls[0]
                print(f"[INFO] Found Issuer Certificate URL: {issuer_url}")

            except ExtensionNotFound:
                QMessageBox.warning(self, "No AIA Extension", "The certificate has no Authority Information Access extension.")
                return

            # Download issuer certificate
            issuer_resp = requests.get(issuer_url, timeout=10)
            if issuer_resp.status_code != 200:
                raise Exception(f"Failed to fetch issuer certificate: HTTP {issuer_resp.status_code}")

            try:
                issuer_cert = x509.load_der_x509_certificate(issuer_resp.content, default_backend())
                print("[INFO] Loaded issuer certificate (DER)")
            except Exception:
                issuer_cert = x509.load_pem_x509_certificate(issuer_resp.content, default_backend())
                print("[INFO] Loaded issuer certificate (PEM)")

            builder = OCSPRequestBuilder()
            builder = builder.add_certificate(cert, issuer_cert, hashes.SHA1())
            req = builder.build()
            req_data = req.public_bytes(serialization.Encoding.DER)

            headers = {'Content-Type': 'application/ocsp-request'}
            ocsp_resp = requests.post(ocsp_url, data=req_data, headers=headers, timeout=10)
            if ocsp_resp.status_code != 200:
                raise Exception(f"OCSP responder returned HTTP {ocsp_resp.status_code}")

            ocsp_response = x509.ocsp.load_der_ocsp_response(ocsp_resp.content)
            status = ocsp_response.response_status

            if status != OCSPResponseStatus.SUCCESSFUL:
                QMessageBox.warning(self, "OCSP Response", f"OCSP response status not successful: {status}")
                return

            cert_status = ocsp_response.certificate_status
            if cert_status == x509.ocsp.OCSPCertStatus.REVOKED:
                msg = "❌ The certificate IS REVOKED according to OCSP."
            elif cert_status == x509.ocsp.OCSPCertStatus.GOOD:
                msg = "✅ The certificate is GOOD according to OCSP."
            else:
                msg = "⚠️ Certificate status is UNKNOWN according to OCSP."

            QMessageBox.information(self, "OCSP Check Result", msg)

        except Exception as e:
            print("[ERROR] OCSP Check failed:")
            traceback.print_exc()
            QMessageBox.critical(self, "OCSP Check Failed", f"An error occurred:\n{str(e)}")

if __name__ == "__main__":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        # Relaunch as admin and exit current instance
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
        sys.exit()

    app = SingleInstanceApp(sys.argv)
    app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    window = CertConverter()
    window.show()
    sys.exit(app.exec_())
