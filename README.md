# CertConverter & Revocation Checker

A PyQt5-based desktop application to **convert digital certificates** (.cer, .pfx) to PEM format and **check their revocation status** using CRL and OCSP protocols. This tool is designed for secure and easy management of certificates issued by trusted authorities like **CCA India 2022 Root**.

---

## Features

- **Convert .cer files to PEM format**  
  Easily convert DER or PEM encoded `.cer` certificate files into `.pem` format for compatibility and usage in various applications.

- **Convert .pfx/.p12 files to certificate.pem and private_key.pem**  
  Extract the certificate and private key from password-protected PFX files, saving them as separate PEM files.

- **Check Certificate Revocation using CRL (Certificate Revocation List)**  
  Verify if a certificate has been revoked by checking the CRL distribution points embedded in the certificate.

- **Check Certificate Status using OCSP (Online Certificate Status Protocol)**  
  Perform real-time revocation checks through OCSP responders for improved security.

- **Single instance enforcement**  
  Prevent multiple instances of the application from running simultaneously to avoid conflicts.

- **Modern UI with dark theme**  
  Utilizes `qdarkstyle` for a clean, dark-themed graphical interface for better usability.

- **Windows Administrator Privileges**  
  Automatically prompts to run with admin rights to ensure proper file access and permissions.

---

## Screenshots

![App GUI]([https://www.managexindia.com/GUI.png](https://github.com/Aniketc068/CertCheckAndConvert/blob/main/GUI.png))

## Supported Certificate Types

- `.cer`, `.crt`, `.pem` — Certificate files in DER or PEM encoding  
- `.pfx`, `.p12` — PKCS#12 archive files containing certificates and private keys

---

## System Requirements

- Python 3.6 or higher
- Windows, macOS, or Linux

## Installation

### 1. Create and Activate Virtual Environment

#### Windows:
```cmd
python -m venv pem
pem\Scripts\activate
```

#### macOS/Linux:
```cmd
python3 -m venv pem
source pem/bin/activate
```

### 2. Install Dependencies
```cmd
pip install -r requirements.txt
```
### 3. Run the application:
```cmd
python cert_converter.py
```

### Version
Current version: 1.0
