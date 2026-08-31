// Package config loads, validates and normalises the exporter configuration.
//
// The YAML schema is unchanged from earlier releases of the exporter: existing
// configuration files keep working. Credentials may additionally be supplied
// through environment variables so that they never have to be written to disk.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Defaults applied when the corresponding key is absent or zero.
const (
	DefaultPollRateSeconds = 10
	DefaultTimeoutSeconds  = 5
)

// Environment variables that override the configuration file. They exist so
// that secrets can be injected by a secret manager or container orchestrator
// instead of being stored in clear text on a mounted volume.
const (
	EnvAddress         = "CSE_ADDRESS"
	EnvUsername        = "CSE_USERNAME"
	EnvPassword        = "CSE_PASSWORD"
	EnvWebAuthUsername = "CSE_WEB_AUTH_USERNAME"
	EnvWebAuthPassword = "CSE_WEB_AUTH_PASSWORD"
)

// redacted replaces secrets in anything that may end up in a log line.
const redacted = "[REDACTED]"

// Config is the exporter configuration.
type Config struct {
	// Address is the switch host, optionally with a port ("192.168.1.1",
	// "switch.lan:8080", "[fd00::1]:80"). No scheme and no path.
	Address string `yaml:"address"`
	// Username and Password authenticate against the switch web interface.
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	// PollRateSeconds is the minimum delay between two polls of the switch.
	// Scrapes arriving sooner are answered from the last result. It shields
	// these low-powered devices from highly available Prometheus pairs and
	// from short scrape intervals. An explicit 0 disables the cache; a nil
	// pointer means the key was absent and the default applies.
	PollRateSeconds *int `yaml:"poll_rate_seconds"`
	// TimeoutSeconds bounds a single HTTP request to the switch.
	TimeoutSeconds *int `yaml:"timeout_seconds"`
	// PoE enables scraping of the PoE pages. Accepts true/false as well as
	// the historical 1/0 spelling.
	PoE FlexBool `yaml:"poe"`
	// Web configures the exporter's own HTTP endpoint.
	Web WebConfig `yaml:"web"`
}

// WebConfig configures the HTTP server exposing the metrics.
type WebConfig struct {
	// TLSCertFile and TLSKeyFile enable HTTPS when both are set.
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	// AuthUsername and AuthPassword enable HTTP basic authentication on the
	// metrics endpoint when both are set.
	AuthUsername string `yaml:"auth_username"`
	AuthPassword string `yaml:"auth_password"`
}

// PollRate returns the minimum delay between two polls of the switch.
func (c Config) PollRate() time.Duration {
	if c.PollRateSeconds == nil {
		return DefaultPollRateSeconds * time.Second
	}
	return time.Duration(*c.PollRateSeconds) * time.Second
}

// Timeout returns the per-request timeout for calls to the switch.
func (c Config) Timeout() time.Duration {
	if c.TimeoutSeconds == nil {
		return DefaultTimeoutSeconds * time.Second
	}
	return time.Duration(*c.TimeoutSeconds) * time.Second
}

// TLSEnabled reports whether the metrics endpoint should be served over HTTPS.
func (c Config) TLSEnabled() bool {
	return c.Web.TLSCertFile != "" && c.Web.TLSKeyFile != ""
}

// AuthEnabled reports whether the metrics endpoint requires basic auth.
func (c Config) AuthEnabled() bool {
	return c.Web.AuthUsername != ""
}

// String implements fmt.Stringer with every secret redacted. It exists so that
// logging a Config, by accident or on purpose, cannot disclose credentials.
func (c Config) String() string {
	c.Password = redactIfSet(c.Password)
	c.Web.AuthPassword = redactIfSet(c.Web.AuthPassword)
	return fmt.Sprintf("address=%s username=%s password=%s poll_rate=%s "+
		"timeout=%s poe=%t tls=%t auth=%t",
		c.Address, c.Username, c.Password, c.PollRate(),
		c.Timeout(), bool(c.PoE), c.TLSEnabled(), c.AuthEnabled())
}

func redactIfSet(s string) string {
	if s == "" {
		return ""
	}
	return redacted
}

// Load reads the configuration from path, applies environment overrides and
// defaults, and validates the result.
//
// A missing file is tolerated when the mandatory values are supplied through
// the environment, which is the usual setup for container deployments.
func Load(path string) (Config, error) {
	var cfg Config

	data, err := os.ReadFile(path) //nolint:gosec // the path is operator supplied by design
	switch {
	case err == nil:
		if err := decode(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parsing %s: %w", path, err)
		}
	case errors.Is(err, fs.ErrNotExist):
		// Fall through: the environment may carry the whole configuration.
	default:
		return Config{}, fmt.Errorf("reading %s: %w", path, err)
	}

	applyEnv(&cfg)
	cfg.Address = normalizeAddress(strings.TrimSpace(cfg.Address))

	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid configuration: %w", err)
	}
	return cfg, nil
}

// decode unmarshals YAML rejecting unknown keys, so that a misspelled option is
// reported instead of being silently ignored.
func decode(data []byte, cfg *Config) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func applyEnv(cfg *Config) {
	for _, o := range []struct {
		env string
		dst *string
	}{
		{EnvAddress, &cfg.Address},
		{EnvUsername, &cfg.Username},
		{EnvPassword, &cfg.Password},
		{EnvWebAuthUsername, &cfg.Web.AuthUsername},
		{EnvWebAuthPassword, &cfg.Web.AuthPassword},
	} {
		if v, ok := os.LookupEnv(o.env); ok && v != "" {
			*o.dst = v
		}
	}
}

// Validate reports the first problem found in the configuration.
func (c Config) Validate() error {
	if err := validateAddress(c.Address); err != nil {
		return err
	}
	if c.Username == "" {
		return fmt.Errorf("username is required (set it in the file or in %s)", EnvUsername)
	}
	if c.Password == "" {
		return fmt.Errorf("password is required (set it in the file or in %s)", EnvPassword)
	}
	if c.TimeoutSeconds != nil && *c.TimeoutSeconds <= 0 {
		return fmt.Errorf("timeout_seconds must be positive, got %d", *c.TimeoutSeconds)
	}
	if c.PollRateSeconds != nil && *c.PollRateSeconds < 0 {
		return fmt.Errorf("poll_rate_seconds must not be negative, got %d", *c.PollRateSeconds)
	}
	return c.Web.validate()
}

func (w WebConfig) validate() error {
	if (w.TLSCertFile == "") != (w.TLSKeyFile == "") {
		return errors.New("web.tls_cert_file and web.tls_key_file must be set together")
	}
	for _, f := range []string{w.TLSCertFile, w.TLSKeyFile} {
		if f == "" {
			continue
		}
		if _, err := os.Stat(f); err != nil {
			return fmt.Errorf("web TLS file: %w", err)
		}
	}
	if (w.AuthUsername == "") != (w.AuthPassword == "") {
		return errors.New("web.auth_username and web.auth_password must be set together")
	}
	return nil
}

// normalizeAddress brackets a bare IPv6 literal so that it can be used as the
// host part of a URL.
func normalizeAddress(addr string) string {
	if addr == "" || strings.HasPrefix(addr, "[") {
		return addr
	}
	if ip := net.ParseIP(addr); ip != nil && strings.Contains(addr, ":") {
		return "[" + addr + "]"
	}
	return addr
}

// validateAddress rejects anything that is not a bare host or host:port. The
// address is concatenated into a URL, so a value carrying a scheme, a path or
// user information would silently produce a request to the wrong place.
func validateAddress(addr string) error {
	if addr == "" {
		return fmt.Errorf("address is required (set it in the file or in %s)", EnvAddress)
	}
	if strings.Contains(addr, "://") || strings.ContainsAny(addr, "/?#@ \t") {
		return fmt.Errorf("address %q must be a bare host or host:port, without scheme, path or credentials", addr)
	}

	host := addr
	if strings.HasPrefix(addr, "[") {
		// Bracketed IPv6 literal, optionally followed by :port.
		end := strings.Index(addr, "]")
		if end < 0 {
			return fmt.Errorf("address %q has an unterminated IPv6 literal", addr)
		}
		host = addr[1:end]
		if net.ParseIP(host) == nil {
			return fmt.Errorf("address %q does not contain a valid IPv6 literal", addr)
		}
		if rest := addr[end+1:]; rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return fmt.Errorf("address %q has trailing characters after the IPv6 literal", addr)
			}
			if err := validatePort(rest[1:]); err != nil {
				return fmt.Errorf("address %q: %w", addr, err)
			}
		}
	} else if h, port, err := net.SplitHostPort(addr); err == nil {
		host = h
		if err := validatePort(port); err != nil {
			return fmt.Errorf("address %q: %w", addr, err)
		}
	} else if strings.Contains(addr, ":") {
		return fmt.Errorf("address %q is not a valid host or host:port (bracket IPv6 literals, e.g. [fd00::1]:80)", addr)
	}

	if host == "" {
		return fmt.Errorf("address %q has an empty host", addr)
	}
	return nil
}

func validatePort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid TCP port %q", port)
	}
	return nil
}

// CheckPermissions reports whether the configuration file is readable by users
// other than its owner. Callers are expected to surface the result as a
// warning: the file normally holds the switch password in clear text.
func CheckPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("%s is readable by other users (mode %#o); run chmod 600 %s", path, mode, path)
	}
	return nil
}

// FlexBool is a boolean that also accepts the integer and string spellings used
// by older configuration files, where PoE support was enabled with `poe: 1`.
type FlexBool bool

// UnmarshalYAML implements yaml.Unmarshaler.
func (b *FlexBool) UnmarshalYAML(value *yaml.Node) error {
	var asBool bool
	if err := value.Decode(&asBool); err == nil {
		*b = FlexBool(asBool)
		return nil
	}
	var asInt int
	if err := value.Decode(&asInt); err == nil {
		*b = asInt != 0
		return nil
	}
	var asString string
	if err := value.Decode(&asString); err == nil {
		parsed, err := strconv.ParseBool(strings.ToLower(strings.TrimSpace(asString)))
		if err == nil {
			*b = FlexBool(parsed)
			return nil
		}
	}
	return fmt.Errorf("line %d: cannot read %q as a boolean, use true/false or 1/0", value.Line, value.Value)
}
