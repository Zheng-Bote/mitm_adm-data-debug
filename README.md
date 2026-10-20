# MitM Admin Data Decryptor (`mitm_adm-data`)

**MitM Admin Data Decryptor** is a standalone desktop application built with [Go](https://golang.org) and [Fyne](https://fyne.io/). It acts as an administrative utility for the Man-in-the-Middle (MitM) Data Aggregator, allowing authorized personnel to securely decrypt payload fragments (e.g., PII data) that were encrypted at rest using Envelope Encryption (AES-GCM).

## Features

- **Cross-Platform**: Runs on Windows and Linux.
- **Encrypted Config Files**: Reads the PostgreSQL connection settings from an AES-256-GCM/Argon2id encrypted `.enc` file (the format produced by `mitm_maintenance_config`). The file is selected inside the application and unlocked with its password. The connection settings are not editable in the UI — the config file is the single source of truth.
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
2. **Load Config**: Click **Browse...**, select an encrypted config file (`*.enc`, e.g. `app/cfg/config.enc`), enter its password and click **Load Config**. The database connection is taken exclusively from the decrypted file; the status line shows the loaded target (`user@host:port/database`). The last used path is remembered, the password is never stored.
   The file must use the `mitm_maintenance_config` format (`salt | nonce | AES-256-GCM ciphertext`, key derived with Argon2id) and contain a `db` section, e.g.:
   ```json
   { "db": { "host": "192.168.0.31", "port": 6543, "user": "mitm_user", "password": "...", "database": "mitm", "sslmode": false } }
   ```
3. **Connect & Test DB**: Verifies the connection defined by the loaded config file. There are no editable connection fields; without a loaded config file the button reports that a config file is required.
4. **Master Key**: Input your base64-encoded Master Key (KEK).
5. **Encrypted JSON Snippet**: Paste the encrypted JSON payload containing `nonce` and `ciphertext` fields.
6. **Decrypt**: Click "Decrypt". The application will automatically fetch the correct wrapped DEK from the database, unwrap it, decrypt the payload, and output the readable JSON.

## Development

```bash
go test ./...
```

The tests decrypt `testdata/db_config.enc`, a fixture generated with the reference implementation in `mitm_maintenance_config/crypto` (fixture password: `code-whale-fixture-pw`, dummy credentials only).

## License

This project is licensed under the Apache License 2.0.
