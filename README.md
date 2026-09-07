# MitM Admin Data Decryptor (`mitm_adm-data`)

**MitM Admin Data Decryptor** is a standalone desktop application built with [Go](https://golang.org) and [Fyne](https://fyne.io/). It acts as an administrative utility for the Man-in-the-Middle (MitM) Data Aggregator, allowing authorized personnel to securely decrypt payload fragments (e.g., PII data) that were encrypted at rest using Envelope Encryption (AES-GCM).

## Features

- **Cross-Platform**: Runs on Windows and Linux.
- **Biometric Authentication**: On Windows, automatically utilizes Windows Hello (via WinRT) to ensure seamless biometric authentication before granting access to the tool.
- **Envelope Decryption**: Securely decrypts JSON payloads (`nonce` + `ciphertext`) using the Master Key (KEK) and the associated Wrapped Data Encryption Keys (DEKs) retrieved directly from the PostgreSQL database.
- **Database Connection Tester**: Built-in functionality to test and verify the connection to the underlying PostgreSQL database.

## Prerequisites

- **Go v1.26+**
- **Linux users**: Require C-development headers for X11/Wayland (e.g., `libgl1-mesa-dev`, `xorg-dev`, `libwayland-dev`, `libxkbcommon-dev`).

## Getting Started

1. Navigate to the directory:
   ```bash
   cd maintenance-layer/mitm_adm-data
   ```
2. Download dependencies and run:
   ```bash
   go mod tidy
   go run .
   ```
3. To compile into a single binary:
   ```bash
   go build -o mitm_adm-data .
   ```

## Usage

1. **Authenticate**: Upon launch, you will be prompted for authentication (e.g., Windows Hello).
2. **Database Settings**: Enter the PostgreSQL connection details (Host, Port, User, Password, Database) and click **Connect & Test DB** to ensure connectivity.
3. **Master Key**: Input your base64-encoded Master Key (KEK).
4. **Encrypted JSON Snippet**: Paste the encrypted JSON payload containing `nonce` and `ciphertext` fields.
5. **Decrypt**: Click "Decrypt". The application will automatically fetch the correct wrapped DEK from the database, unwrap it, decrypt the payload, and output the readable JSON.

## License

This project is licensed under the Apache License 2.0.
