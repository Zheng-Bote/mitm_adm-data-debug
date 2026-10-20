# Changelog

All notable changes to the `mitm_adm-data` project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-20

### Added
- Load the PostgreSQL connection settings from an AES-256-GCM/Argon2id encrypted config file (`mitm_maintenance_config` format), selectable inside the application via file dialog. The password is requested per session and never stored.
- Connection URLs are built with proper URL escaping, so passwords containing `@`, `:` or `/` work.
- SSL mode comes from the config file's `sslmode` field (`false` -> `disable`, `true` -> `require`).
- Unit and UI tests, including a fixture produced by the reference encryption implementation.

### Changed
- Database connection test runs asynchronously so the UI stays responsive.
- Default window size reduced to fit the simplified layout.
- **The PostgreSQL connection fields (Host, Port, User, Password, Database, SSL Mode)
  are no longer displayed.** The connection now comes exclusively from the loaded
  encrypted config file; only **Connect & Test DB** remains. Without a loaded
  config, both Connect and Decrypt report that a config file is required.
- Application now starts with a unique app ID (`app.NewWithID`), so the
  Preferences API (last config path) works instead of logging an error.
- Window content is built inside `fyne.Do`, as required by the Fyne threading model.

### Fixed
- Crash (nil pointer dereference) when clicking **Browse...**: `FileDialog.Resize`
  was called before `Show`, but its internal dialog only exists afterwards. The
  dialog now keeps its natural size instead of an explicit one.
- Chosen config paths are converted from the file URI to an OS path, so Browse
  also works on Windows (Fyne reports `/C:/dir/config.enc` there).

## [0.1.0] - 2026-09-07

### Added
- Initial release of the `mitm_adm-data` Fyne-based desktop application.
- Cross-platform support for Linux and Windows.
- Implemented **Windows Hello Authentication** via WinRT for secure application startup on Windows environments.
- Added input form for dynamic PostgreSQL database connection configuration.
- Added a "Connect & Test DB" button to verify database connectivity visually in the UI.
- Implemented Envelope Decryption logic (AES-GCM) that seamlessly iterates through active Data Encryption Keys (DEKs) from the database to decrypt payloads.
- Automatic JSON parsing and formatting (pretty-print) for decrypted output payload results.
