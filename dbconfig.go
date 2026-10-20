package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
)

// dbConnectionConfig mirrors the "db" section of the encrypted configuration
// files produced by the mitm_maintenance_config tool. Only the fields used by
// this application are evaluated; the remaining ones are kept so that a whole
// configuration can be decoded without losing information.
type dbConnectionConfig struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	User           string `json:"user"`
	Password       string `json:"password"`
	Database       string `json:"database"`
	DBConnectDelay int    `json:"db_connect_delay,omitempty"`
	SSLMode        bool   `json:"sslmode,omitempty"`
	MaxConns       int    `json:"max_conns,omitempty"`
}

// LoadEncryptedDBConfig reads an AES-256-GCM/Argon2id encrypted JSON config
// file, decrypts it with the given password and returns the contained database
// section. Both the nested layout used by mitm_maintenance_config
// ({"db": {...}}) and a flat database object are accepted.
func LoadEncryptedDBConfig(path, password string) (*dbConnectionConfig, error) {
	encrypted, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read config file: %w", err)
	}

	plaintext, err := DecryptAESGCM(encrypted, []byte(password))
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt config file (wrong password or corrupt file): %w", err)
	}

	return parseDBConfig(plaintext)
}

// parseDBConfig extracts the database section from decrypted configuration
// JSON and validates it.
func parseDBConfig(plaintext []byte) (*dbConnectionConfig, error) {
	var fileCfg struct {
		DB *dbConnectionConfig `json:"db"`
	}
	if err := json.Unmarshal(plaintext, &fileCfg); err != nil {
		return nil, fmt.Errorf("decrypted config is not valid JSON: %w", err)
	}

	cfg := fileCfg.DB
	if cfg == nil {
		// Legacy flat layout: host/user/password/database at the top level.
		cfg = &dbConnectionConfig{}
		if err := json.Unmarshal(plaintext, cfg); err != nil {
			return nil, fmt.Errorf(`decrypted config has no "db" section: %w`, err)
		}
	}

	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// normalize trims whitespace, applies the PostgreSQL default port and verifies
// that all mandatory connection fields are present.
func (c *dbConnectionConfig) normalize() error {
	c.Host = strings.TrimSpace(c.Host)
	c.User = strings.TrimSpace(c.User)
	c.Database = strings.TrimSpace(c.Database)
	if c.Port == 0 {
		c.Port = 5432
	}

	switch {
	case c.Host == "":
		return errors.New(`database host is missing ("db.host")`)
	case c.User == "":
		return errors.New(`database user is missing ("db.user")`)
	case c.Database == "":
		return errors.New(`database name is missing ("db.database")`)
	case c.Port < 1 || c.Port > 65535:
		return fmt.Errorf("invalid database port: %d", c.Port)
	}
	return nil
}

// SSLModeString maps the boolean sslmode flag of the config file to a libpq
// sslmode value.
func (c dbConnectionConfig) SSLModeString() string {
	if c.SSLMode {
		return "require"
	}
	return "disable"
}

// ConnString returns the connection string defined by this config file.
func (c dbConnectionConfig) ConnString() string {
	return c.DSN(c.SSLModeString())
}

// dbTarget holds the database connection loaded from the encrypted config file.
// It stays empty until a config file has been decrypted successfully.
type dbTarget struct {
	mu  sync.Mutex
	cfg *dbConnectionConfig
}

func (t *dbTarget) set(cfg *dbConnectionConfig) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cfg = cfg
}

func (t *dbTarget) clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cfg = nil
}

// connString returns the DSN of the loaded config or an error if no config file
// has been loaded yet.
func (t *dbTarget) connString() (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cfg == nil {
		return "", errors.New("no config file loaded - load an encrypted config file first")
	}
	return t.cfg.ConnString(), nil
}

// summary describes the loaded target for display, e.g. "user@host:port/db".
func (t *dbTarget) summary() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cfg == nil {
		return ""
	}
	return fmt.Sprintf("%s@%s:%d/%s", t.cfg.User, t.cfg.Host, t.cfg.Port, t.cfg.Database)
}

// DSN builds a PostgreSQL connection string. sslMode must be one of "disable",
// "prefer" or "require". Credentials are escaped so that passwords containing
// special characters cannot break the URL.
func (c dbConnectionConfig) DSN(sslMode string) string {
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(c.User, c.Password),
		Host:   net.JoinHostPort(c.Host, strconv.Itoa(c.Port)),
		Path:   "/" + c.Database,
	}
	query := u.Query()
	query.Set("sslmode", sslMode)
	u.RawQuery = query.Encode()
	return u.String()
}
