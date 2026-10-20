package main

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

// fixturePassword belongs to testdata/db_config.enc. The fixture was generated
// with the mitm_maintenance_config reference implementation (AES-256-GCM,
// Argon2id, format: salt|nonce|ciphertext) to prove format compatibility.
const fixturePassword = "code-whale-fixture-pw"

func testConfig() dbConnectionConfig {
	return dbConnectionConfig{
		Host:     "192.168.0.31",
		Port:     6543,
		User:     "test_user",
		Password: "s3cr3t@user:pw/1",
		Database: "testdb",
	}
}

func TestLoadEncryptedDBConfig(t *testing.T) {
	cfg, err := LoadEncryptedDBConfig(filepath.Join("testdata", "db_config.enc"), fixturePassword)
	if err != nil {
		t.Fatalf("LoadEncryptedDBConfig: %v", err)
	}

	want := testConfig()
	if cfg.Host != want.Host {
		t.Errorf("Host = %q, want %q", cfg.Host, want.Host)
	}
	if cfg.Port != want.Port {
		t.Errorf("Port = %d, want %d", cfg.Port, want.Port)
	}
	if cfg.User != want.User {
		t.Errorf("User = %q, want %q", cfg.User, want.User)
	}
	if cfg.Password != want.Password {
		t.Errorf("Password = %q, want %q", cfg.Password, want.Password)
	}
	if cfg.Database != want.Database {
		t.Errorf("Database = %q, want %q", cfg.Database, want.Database)
	}
}

func TestLoadEncryptedDBConfigWrongPassword(t *testing.T) {
	if _, err := LoadEncryptedDBConfig(filepath.Join("testdata", "db_config.enc"), "wrong-password"); err == nil {
		t.Fatal("expected an error for a wrong password, got nil")
	}
}

func TestLoadEncryptedDBConfigMissingFile(t *testing.T) {
	if _, err := LoadEncryptedDBConfig(filepath.Join("testdata", "does-not-exist.enc"), fixturePassword); err == nil {
		t.Fatal("expected an error for a missing file, got nil")
	}
}

func TestParseDBConfigFlatLayout(t *testing.T) {
	plain := []byte(`{"host":"10.0.0.5","port":5432,"user":"u","password":"p","database":"d"}`)

	cfg, err := parseDBConfig(plain)
	if err != nil {
		t.Fatalf("parseDBConfig: %v", err)
	}
	if cfg.Host != "10.0.0.5" || cfg.Database != "d" {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

func TestParseDBConfigDefaultsPort(t *testing.T) {
	cfg, err := parseDBConfig([]byte(`{"db":{"host":"h","user":"u","database":"d"}}`))
	if err != nil {
		t.Fatalf("parseDBConfig: %v", err)
	}
	if cfg.Port != 5432 {
		t.Errorf("Port = %d, want default 5432", cfg.Port)
	}
}

func TestParseDBConfigRejectsIncompleteConfig(t *testing.T) {
	cases := map[string]string{
		"missing host":     `{"db":{"user":"u","database":"d"}}`,
		"missing user":     `{"db":{"host":"h","database":"d"}}`,
		"missing database": `{"db":{"host":"h","user":"u"}}`,
		"invalid port":     `{"db":{"host":"h","user":"u","database":"d","port":70000}}`,
		"invalid json":     `not json`,
	}

	for name, plain := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseDBConfig([]byte(plain)); err == nil {
				t.Fatalf("expected an error for %q, got nil", plain)
			}
		})
	}
}

func TestDSNEscapesCredentials(t *testing.T) {
	cfg := testConfig()

	dsn := cfg.DSN("disable")
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("DSN is not a valid URL (%q): %v", dsn, err)
	}

	password, _ := u.User.Password()
	if password != cfg.Password {
		t.Errorf("password round-trip = %q, want %q", password, cfg.Password)
	}
	if u.User.Username() != cfg.User {
		t.Errorf("user = %q, want %q", u.User.Username(), cfg.User)
	}
	if u.Host != "192.168.0.31:6543" {
		t.Errorf("host = %q, want %q", u.Host, "192.168.0.31:6543")
	}
	if u.Path != "/testdb" {
		t.Errorf("path = %q, want %q", u.Path, "/testdb")
	}
	if got := u.Query().Get("sslmode"); got != "disable" {
		t.Errorf("sslmode = %q, want %q", got, "disable")
	}
}

func TestSSLModeString(t *testing.T) {
	cfg := testConfig()

	cfg.SSLMode = false
	if got := cfg.SSLModeString(); got != "disable" {
		t.Errorf("SSLModeString() = %q, want %q", got, "disable")
	}

	cfg.SSLMode = true
	if got := cfg.SSLModeString(); got != "require" {
		t.Errorf("SSLModeString() = %q, want %q", got, "require")
	}
}

func TestConnStringUsesConfigSSLMode(t *testing.T) {
	cfg := testConfig()

	cfg.SSLMode = true
	u, err := url.Parse(cfg.ConnString())
	if err != nil {
		t.Fatalf("ConnString is not a valid URL: %v", err)
	}
	if got := u.Query().Get("sslmode"); got != "require" {
		t.Errorf("sslmode = %q, want %q", got, "require")
	}
}

func TestDBTargetWithoutConfig(t *testing.T) {
	target := &dbTarget{}

	if _, err := target.connString(); err == nil {
		t.Fatal("expected an error before a config file was loaded, got nil")
	}
	if got := target.summary(); got != "" {
		t.Errorf("summary() = %q, want empty", got)
	}
}

func TestDBTargetSetAndClear(t *testing.T) {
	target := &dbTarget{}
	cfg := testConfig()

	target.set(&cfg)

	dsn, err := target.connString()
	if err != nil {
		t.Fatalf("connString: %v", err)
	}
	if u, err := url.Parse(dsn); err != nil || u.Host != "192.168.0.31:6543" {
		t.Errorf("unexpected DSN %q (%v)", dsn, err)
	}

	if got, want := target.summary(), "test_user@192.168.0.31:6543/testdb"; got != want {
		t.Errorf("summary() = %q, want %q", got, want)
	}

	target.clear()
	if _, err := target.connString(); err == nil {
		t.Fatal("expected an error after clear(), got nil")
	}
}

func TestDecryptAESGCMRejectsShortInput(t *testing.T) {
	if _, err := DecryptAESGCM(make([]byte, 10), []byte("pw")); err == nil {
		t.Fatal("expected an error for truncated input, got nil")
	}
}

func TestDecryptAESGCMRejectsCorruptData(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "db_config.enc"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	data[len(data)-1] ^= 0xff

	if _, err := DecryptAESGCM(data, []byte(fixturePassword)); err == nil {
		t.Fatal("expected an error for tampered ciphertext, got nil")
	}
}
