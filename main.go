// Command cheap-switch-exporter exposes port and PoE statistics of low-cost,
// SNMP-less network switches as Prometheus metrics.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"cheap-switch-exporter/internal/collector"
	"cheap-switch-exporter/internal/config"
	"cheap-switch-exporter/internal/switchclient"
)

// Version is set at build time with -ldflags "-X main.Version=...".
var Version = "dev"

const (
	defaultConfigPath = "config.yaml"
	defaultListenAddr = ":8080"
	shutdownTimeout   = 10 * time.Second
	// healthPath is reserved: container health checks and Kubernetes probes
	// depend on it answering without touching the switch.
	healthPath = "/healthz"
)

func main() {
	// The work happens in a function that returns, so the deferred signal
	// cleanup runs before the process exits.
	os.Exit(realMain())
}

func realMain() int {
	// The signal context lets an in-flight scrape finish while new connections
	// are refused, instead of dropping requests on the floor.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "cheap-switch-exporter: %v\n", err)
		return 1
	}
	return 0
}

type options struct {
	configPath    string
	listenAddr    string
	telemetryPath string
	logLevel      string
	logFormat     string
	showVersion   bool
	// deprecated collects notices to log once the logger exists.
	deprecated []string
}

func parseFlags(args []string, out io.Writer) (options, error) {
	var opts options
	var legacyPort string

	fs := flag.NewFlagSet("cheap-switch-exporter", flag.ContinueOnError)
	fs.SetOutput(out)
	// -c is kept as a short alias because the container image has always
	// invoked the binary with it.
	fs.StringVar(&opts.configPath, "c", defaultConfigPath, "Path to the configuration file (shorthand).")
	fs.StringVar(&opts.configPath, "config", defaultConfigPath, "Path to the configuration file.")
	fs.StringVar(&opts.configPath, "config-file", defaultConfigPath, "Path to the configuration file (alias of -config).")
	fs.StringVar(&opts.listenAddr, "web.listen-address", defaultListenAddr, "Address to listen on for the metrics endpoint.")
	fs.StringVar(&legacyPort, "port", "", "Deprecated alias of -web.listen-address.")
	fs.StringVar(&opts.telemetryPath, "web.telemetry-path", "/metrics", "Path under which to expose the metrics.")
	fs.StringVar(&opts.logLevel, "log.level", "info", "Log level: debug, info, warn or error.")
	fs.StringVar(&opts.logFormat, "log.format", "text", "Log format: text or json.")
	fs.BoolVar(&opts.showVersion, "version", false, "Print the version and exit.")

	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if fs.NArg() > 0 {
		return options{}, fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}

	provided := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	if provided["port"] {
		if provided["web.listen-address"] {
			return options{}, errors.New("-port is a deprecated alias of -web.listen-address; set only one")
		}
		opts.listenAddr = legacyPort
		opts.deprecated = append(opts.deprecated,
			"-port is deprecated, use -web.listen-address")
	}

	if !strings.HasPrefix(opts.telemetryPath, "/") {
		return options{}, fmt.Errorf("web.telemetry-path must start with '/', got %q", opts.telemetryPath)
	}
	// Serving metrics from the health path would shadow the liveness probe and
	// make every health check poll the switch.
	if opts.telemetryPath == healthPath {
		return options{}, fmt.Errorf("web.telemetry-path must not be %s, that path is reserved for the liveness probe", healthPath)
	}
	return opts, nil
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	opts, err := parseFlags(args, stdout)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if opts.showVersion {
		_, _ = fmt.Fprintf(stdout, "cheap-switch-exporter %s (%s)\n", Version, runtime.Version())
		return nil
	}

	logger, err := newLogger(stdout, opts.logLevel, opts.logFormat)
	if err != nil {
		return err
	}
	for _, notice := range opts.deprecated {
		logger.Warn("deprecated flag", "detail", notice)
	}

	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	if err := config.CheckPermissions(opts.configPath); err != nil {
		logger.Warn("insecure configuration file permissions", "err", err)
	}
	logger.Info("configuration loaded", "path", opts.configPath, "config", cfg.String())

	client := switchclient.New(switchclient.Options{
		Address:  cfg.Address,
		Username: cfg.Username,
		Password: cfg.Password,
		Timeout:  cfg.Timeout(),
		Logger:   logger,
	})

	// A dedicated registry keeps the exposed set explicit and makes the
	// exporter safe to instantiate more than once, for instance in tests.
	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collector.New(ctx, collector.Options{
			Client:      client,
			Logger:      logger,
			PoE:         bool(cfg.PoE),
			Timeout:     cfg.Timeout(),
			MinInterval: cfg.PollRate(),
			Version:     Version,
		}),
	)

	srv := newServer(opts, cfg, registry, logger)
	return serve(ctx, srv, cfg, logger)
}

func newLogger(w io.Writer, level, format string) (*slog.Logger, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("invalid log.level %q: %w", level, err)
	}
	handlerOpts := &slog.HandlerOptions{Level: lvl}

	switch format {
	case "text", "logfmt":
		return slog.New(slog.NewTextHandler(w, handlerOpts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, handlerOpts)), nil
	default:
		return nil, fmt.Errorf("invalid log.format %q: want text or json", format)
	}
}

func newServer(opts options, cfg config.Config, registry *prometheus.Registry, logger *slog.Logger) *http.Server {
	errLog := slog.NewLogLogger(logger.Handler(), slog.LevelError)

	// A scrape performs up to three sequential requests to the switch, so the
	// handler and write budgets have to be derived from the device timeout.
	scrapeBudget := 3*cfg.Timeout() + 2*time.Second

	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		ErrorLog: errLog,
		// Serve whatever could be collected instead of failing the whole
		// scrape when a single collector misbehaves.
		ErrorHandling: promhttp.ContinueOnError,
		Registry:      registry,
		// The device is shielded by the collector mutex and by
		// poll_rate_seconds, not by this limit: it only decides when the
		// exporter starts refusing its own scrapers. Keep it well above any
		// realistic number of Prometheus servers plus health checks.
		MaxRequestsInFlight: 10,
		Timeout:             scrapeBudget,
		// Deliberately not enabling OpenMetrics. It requires counter series to
		// be named <name>_total; the historical names here are not, so the
		// OpenMetrics encoder would have to downgrade every packet counter to
		// type "unknown". Prometheus prefers OpenMetrics when it is offered, so
		// enabling it would lose the counter type on every scrape. Renaming the
		// counters is the real fix and needs a major version.
		EnableOpenMetrics: false,
	})
	handler = promhttp.InstrumentMetricHandler(registry, handler)
	if cfg.AuthEnabled() {
		handler = basicAuth(handler, cfg.Web.AuthUsername, cfg.Web.AuthPassword)
	}

	mux := http.NewServeMux()
	mux.Handle(opts.telemetryPath, handler)
	// Both extra routes are registered defensively: http.ServeMux panics on a
	// duplicate pattern, and the telemetry path comes from a flag.
	if opts.telemetryPath != healthPath {
		// Liveness only: it must not touch the switch, otherwise a container
		// health check would poll the device forever.
		mux.HandleFunc(healthPath, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "ok\n")
		})
	}
	if opts.telemetryPath != "/" {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			// The path is operator supplied; escape it rather than trusting it.
			_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Cheap Switch Exporter</title></head>
<body><h1>Cheap Switch Exporter</h1><p><a href="%s">Metrics</a></p></body></html>`,
				html.EscapeString(opts.telemetryPath))
		})
	}

	return &http.Server{
		Addr:    opts.listenAddr,
		Handler: mux,
		// Bounded read phases close the door on slow-header (Slowloris) clients.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      scrapeBudget + 5*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
		ErrorLog:          errLog,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

func serve(ctx context.Context, srv *http.Server, cfg config.Config, logger *slog.Logger) error {
	scheme := "http"
	if cfg.TLSEnabled() {
		scheme = "https"
	}
	logger.Info("starting exporter", "version", Version, "address", srv.Addr, "scheme", scheme)
	if !cfg.AuthEnabled() && !isLoopback(srv.Addr) {
		logger.Warn("metrics endpoint is exposed without authentication; " +
			"set web.auth_username and web.auth_password, or bind to 127.0.0.1")
	}

	errCh := make(chan error, 1)
	go func() {
		if cfg.TLSEnabled() {
			errCh <- srv.ListenAndServeTLS(cfg.Web.TLSCertFile, cfg.Web.TLSKeyFile)
			return
		}
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		// ErrServerClosed here would mean somebody else closed the server.
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("http server: %w", err)
		}
		return nil
	case <-ctx.Done():
		logger.Info("shutdown requested, draining connections")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	logger.Info("shutdown complete")
	return nil
}

// basicAuth guards h with HTTP basic authentication. Credentials are compared as
// fixed-length digests in constant time so that neither their content nor their
// length leaks through response timing.
func basicAuth(h http.Handler, username, password string) http.Handler {
	wantUser := sha256.Sum256([]byte(username))
	wantPass := sha256.Sum256([]byte(password))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if ok {
			gotUser := sha256.Sum256([]byte(user))
			gotPass := sha256.Sum256([]byte(pass))
			if subtle.ConstantTimeCompare(gotUser[:], wantUser[:]) == 1 &&
				subtle.ConstantTimeCompare(gotPass[:], wantPass[:]) == 1 {
				h.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="metrics", charset="UTF-8"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

// isLoopback reports whether addr binds the loopback interface only.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
