package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// clearEnv neutralises the credential overrides so a developer's shell cannot
// change the outcome of a test.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, env := range []string{EnvAddress, EnvUsername, EnvPassword, EnvWebAuthUsername, EnvWebAuthPassword} {
		t.Setenv(env, "")
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

func TestLoadAppliesDefaults(t *testing.T) {
	clearEnv(t)
	path := writeConfig(t, `
address: "192.168.1.1"
username: "admin"
password: "admin"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PollRate() != DefaultPollRateSeconds*time.Second {
		t.Errorf("PollRate = %v, want %ds", cfg.PollRate(), DefaultPollRateSeconds)
	}
	if cfg.Timeout() != DefaultTimeoutSeconds*time.Second {
		t.Errorf("Timeout = %v, want %ds", cfg.Timeout(), DefaultTimeoutSeconds)
	}
	if cfg.PoE {
		t.Error("PoE should default to disabled")
	}
}

// The historical configuration shape, including `poe: 0`, has to keep working.
func TestLoadLegacyConfig(t *testing.T) {
	clearEnv(t)
	path := writeConfig(t, `---
address: "192.168.1.1"
username: "admin"
password: "admin"
poll_rate_seconds: 30
timeout_seconds: 3
poe: 1
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PollRate() != 30*time.Second || cfg.Timeout() != 3*time.Second {
		t.Errorf("durations = %v/%v, want 30s/3s", cfg.PollRate(), cfg.Timeout())
	}
	if !cfg.PoE {
		t.Error("poe: 1 should enable PoE")
	}
}

func TestFlexBool(t *testing.T) {
	tests := map[string]bool{
		"poe: 1":        true,
		"poe: 0":        false,
		"poe: true":     true,
		"poe: false":    false,
		"poe: \"true\"": true,
		"poe: \"0\"":    false,
	}
	for body, want := range tests {
		t.Run(body, func(t *testing.T) {
			clearEnv(t)
			path := writeConfig(t, "address: h\nusername: u\npassword: p\n"+body+"\n")
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if bool(cfg.PoE) != want {
				t.Errorf("PoE = %t, want %t", cfg.PoE, want)
			}
		})
	}
}

func TestFlexBoolRejectsGarbage(t *testing.T) {
	clearEnv(t)
	path := writeConfig(t, "address: h\nusername: u\npassword: p\npoe: maybe\n")
	_, err := Load(path)
	if err == nil {
		t.Fatal("want an error for a non-boolean poe value")
	}
	if !strings.Contains(err.Error(), "boolean") {
		t.Errorf("err = %v, want it to mention booleans", err)
	}
}

// A misspelled key used to be ignored silently, which is how an operator ends up
// with a timeout that was never applied.
func TestLoadRejectsUnknownKeys(t *testing.T) {
	clearEnv(t)
	path := writeConfig(t, "address: h\nusername: u\npassword: p\ntimeout_second: 5\n")
	_, err := Load(path)
	if err == nil {
		t.Fatal("want an error for an unknown key")
	}
	if !strings.Contains(err.Error(), "timeout_second") {
		t.Errorf("err = %v, want it to name the offending key", err)
	}
}

func TestLoadEnvironmentOverridesFile(t *testing.T) {
	clearEnv(t)
	path := writeConfig(t, "address: file-host\nusername: file-user\npassword: file-pass\n")
	t.Setenv(EnvAddress, "env-host")
	t.Setenv(EnvPassword, "env-pass")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Address != "env-host" || cfg.Password != "env-pass" {
		t.Errorf("address/password = %s/%s, want the environment values", cfg.Address, cfg.Password)
	}
	if cfg.Username != "file-user" {
		t.Errorf("username = %s, want the file value to survive", cfg.Username)
	}
}

// Containers can supply the whole configuration through the environment, so a
// missing file must not be fatal on its own.
func TestLoadWithoutFile(t *testing.T) {
	clearEnv(t)
	t.Setenv(EnvAddress, "10.0.0.1")
	t.Setenv(EnvUsername, "admin")
	t.Setenv(EnvPassword, "secret")

	cfg, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Address != "10.0.0.1" {
		t.Errorf("address = %s", cfg.Address)
	}
}

func TestLoadWithoutFileOrEnvFails(t *testing.T) {
	clearEnv(t)
	_, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil {
		t.Fatal("want an error when neither the file nor the environment provide anything")
	}
}

func TestValidateAddress(t *testing.T) {
	valid := []string{
		"192.168.1.1", "switch.lan", "switch.lan:8080", "10.0.0.1:80", "[fd00::1]:80", "[fd00::1]",
	}
	for _, addr := range valid {
		if err := validateAddress(addr); err != nil {
			t.Errorf("validateAddress(%q) = %v, want nil", addr, err)
		}
	}

	invalid := []string{
		"",
		"http://192.168.1.1",
		"192.168.1.1/port.cgi",
		"user@192.168.1.1",
		"192.168.1.1:0",
		"192.168.1.1:70000",
		"192.168.1.1:http",
		"switch lan",
	}
	for _, addr := range invalid {
		if err := validateAddress(addr); err == nil {
			t.Errorf("validateAddress(%q) = nil, want an error", addr)
		}
	}
}

// A bare IPv6 literal has to be bracketed before it can be used as a URL host.
func TestLoadBracketsIPv6(t *testing.T) {
	clearEnv(t)
	path := writeConfig(t, "address: \"fd00::1\"\nusername: u\npassword: p\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Address != "[fd00::1]" {
		t.Errorf("address = %q, want [fd00::1]", cfg.Address)
	}
}

// An explicit `poll_rate_seconds: 0` means "poll on every scrape". Treating the
// zero value as "absent" would silently substitute the default instead.
func TestLoadDistinguishesExplicitZeroFromAbsent(t *testing.T) {
	clearEnv(t)

	explicit := writeConfig(t, "address: h\nusername: u\npassword: p\npoll_rate_seconds: 0\n")
	cfg, err := Load(explicit)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PollRate() != 0 {
		t.Errorf("PollRate = %v for an explicit 0, want 0", cfg.PollRate())
	}

	absent := writeConfig(t, "address: h\nusername: u\npassword: p\n")
	cfg, err = Load(absent)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PollRate() != DefaultPollRateSeconds*time.Second {
		t.Errorf("PollRate = %v when the key is absent, want the default", cfg.PollRate())
	}
}

func TestValidateRejectsBadDurations(t *testing.T) {
	base := Config{Address: "h", Username: "u", Password: "p"}

	zero := 0
	cfg := base
	cfg.TimeoutSeconds = &zero
	if err := cfg.Validate(); err == nil {
		t.Error("want an error for an explicit zero timeout")
	}

	negative := -1
	cfg = base
	cfg.PollRateSeconds = &negative
	if err := cfg.Validate(); err == nil {
		t.Error("want an error for a negative poll rate")
	}

	// Absent keys fall back to the defaults and must validate.
	if err := base.Validate(); err != nil {
		t.Errorf("Validate with absent durations = %v, want nil", err)
	}
	if base.Timeout() != DefaultTimeoutSeconds*time.Second {
		t.Errorf("Timeout = %v, want the default", base.Timeout())
	}
}

func TestValidateWebSection(t *testing.T) {
	base := Config{Address: "h", Username: "u", Password: "p"}

	cfg := base
	cfg.Web.TLSCertFile = "cert.pem"
	if err := cfg.Validate(); err == nil {
		t.Error("want an error when only the certificate is set")
	}

	cfg = base
	cfg.Web.AuthUsername = "prom"
	if err := cfg.Validate(); err == nil {
		t.Error("want an error when only the auth username is set")
	}

	cfg = base
	cfg.Web.AuthUsername = "prom"
	cfg.Web.AuthPassword = "pw"
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate = %v, want nil", err)
	}
	if !cfg.AuthEnabled() {
		t.Error("AuthEnabled should report true")
	}
}

func TestValidateWebTLSFilesMustExist(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	for _, f := range []string{cert, key} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cfg := Config{Address: "h", Username: "u", Password: "p"}
	cfg.Web.TLSCertFile = cert
	cfg.Web.TLSKeyFile = key
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate = %v, want nil", err)
	}
	if !cfg.TLSEnabled() {
		t.Error("TLSEnabled should report true")
	}

	cfg.Web.TLSKeyFile = filepath.Join(dir, "absent.pem")
	if err := cfg.Validate(); err == nil {
		t.Error("want an error for a missing key file")
	}
}

// Anything that can reach a log line must not carry the credentials.
func TestStringRedactsSecrets(t *testing.T) {
	cfg := Config{
		Address:  "10.0.0.1",
		Username: "admin",
		Password: "sup3rs3cret",
		Web:      WebConfig{AuthUsername: "prom", AuthPassword: "another-secret"},
	}
	got := cfg.String()
	for _, secret := range []string{"sup3rs3cret", "another-secret"} {
		if strings.Contains(got, secret) {
			t.Errorf("String() leaked %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, redacted) {
		t.Errorf("String() = %s, want a redaction marker", got)
	}
	// Non-secret fields are still useful for diagnostics.
	if !strings.Contains(got, "10.0.0.1") || !strings.Contains(got, "admin") {
		t.Errorf("String() = %s, want the address and username", got)
	}
}

// The shipped example must stay loadable: strict decoding turns any drift
// between the documentation and the schema into a failure here.
func TestExampleConfigIsValid(t *testing.T) {
	clearEnv(t)
	cfg, err := Load(filepath.Join("..", "..", "config.yaml.example"))
	if err != nil {
		t.Fatalf("config.yaml.example does not load: %v", err)
	}
	if cfg.Address == "" || cfg.Username == "" || cfg.Password == "" {
		t.Errorf("the example is incomplete: %s", cfg.String())
	}
}

func TestCheckPermissions(t *testing.T) {
	dir := t.TempDir()

	private := filepath.Join(dir, "private.yaml")
	if err := os.WriteFile(private, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckPermissions(private); err != nil {
		t.Errorf("CheckPermissions(0600) = %v, want nil", err)
	}

	world := filepath.Join(dir, "world.yaml")
	if err := os.WriteFile(world, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckPermissions(world); err == nil {
		t.Error("CheckPermissions(0644) = nil, want a warning")
	}

	if err := CheckPermissions(filepath.Join(dir, "absent.yaml")); err != nil {
		t.Errorf("CheckPermissions(absent) = %v, want nil", err)
	}
}
