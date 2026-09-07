# Changelog

All notable changes to the `mitm_adm-data` project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-07

### Added
- Initial release of the `mitm_adm-data` Fyne-based desktop application.
- Cross-platform support for Linux and Windows.
- Implemented **Windows Hello Authentication** via WinRT for secure application startup on Windows environments.
- Added input form for dynamic PostgreSQL database connection configuration.
- Added a "Connect & Test DB" button to verify database connectivity visually in the UI.
- Implemented Envelope Decryption logic (AES-GCM) that seamlessly iterates through active Data Encryption Keys (DEKs) from the database to decrypt payloads.
- Automatic JSON parsing and formatting (pretty-print) for decrypted output payload results.
