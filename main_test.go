package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"cheap-switch-exporter/internal/config"
)

func TestParseFlagsDefaults(t *testing.T) {
	opts, err := parseFlags(nil, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if opts.configPath != defaultConfigPath {
		t.Errorf("configPath = %q, want %q", opts.configPath, defaultConfigPath)
	}
	if opts.listenAddr != defaultListenAddr {
		t.Errorf("listenAddr = %q, want %q", opts.listenAddr, defaultListenAddr)
	}
	if opts.telemetryPath != "/metrics" {
		t.Errorf("telemetryPath = %q, want /metrics", opts.telemetryPath)
	}
}

// The container image has always started the binary with "-c <path>". That flag
// did not exist before, so the configured path was silently ignored.
func TestParseFlagsConfigAliases(t *testing.T) {
	for _, args := range [][]string{
		{"-c", "/etc/cse/config.yaml"},
		{"--config", "/etc/cse/config.yaml"},
		{"-config=/etc/cse/config.yaml"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			opts, err := parseFlags(args, io.Discard)
			if err != nil {
				t.Fatalf("parseFlags: %v", err)
			}
			if opts.configPath != "/etc/cse/config.yaml" {
				t.Errorf("configPath = %q", opts.configPath)
			}
		})
	}
}

func TestParseFlagsRejectsBadInput(t *testing.T) {
	tests := map[string][]string{
		"relative telemetry path": {"--web.telemetry-path", "metrics"},
		"positional argument":     {"config.yaml"},
		"unknown flag":            {"--nope"},
		// Serving metrics from the probe path would make every container health
		// check poll the switch.
		"reserved health path": {"--web.telemetry-path", healthPath},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseFlags(args, io.Discard); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

// http.ServeMux panics on a duplicate pattern, and the telemetry path comes from
// a flag, so every value that collides with a built-in route must be handled.
func TestNewServerHandlesRouteCollisions(t *testing.T) {
	logger, err := newLogger(io.Discard, "error", "text")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Address: "h", Username: "u", Password: "p"}

	for _, path := range []string{"/", "/metrics", healthPath, "/a/b"} {
		t.Run(path, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("newServer panicked for telemetry-path=%s: %v", path, r)
				}
			}()
			srv := newServer(options{listenAddr: "127.0.0.1:0", telemetryPath: path},
				cfg, prometheus.NewRegistry(), logger)
			if srv.Handler == nil {
				t.Fatal("no handler was installed")
			}
		})
	}
}

// Serving metrics at the root must still work, and must not shadow the probe.
func TestNewServerMetricsAtRoot(t *testing.T) {
	logger, err := newLogger(io.Discard, "error", "text")
	if err != nil {
		t.Fatal(err)
	}
	reg := prometheus.NewRegistry()
	srv := newServer(options{listenAddr: "127.0.0.1:0", telemetryPath: "/"},
		config.Config{Address: "h", Username: "u", Password: "p"}, reg, logger)

	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("GET / = %d, want 200", rec.Code)
	}

	rec = httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, healthPath, nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ok") {
		t.Errorf("GET %s = %d %q, want the probe to survive", healthPath, rec.Code, rec.Body.String())
	}
}

// The landing page interpolates an operator supplied path; it must be escaped.
func TestLandingPageEscapesTelemetryPath(t *testing.T) {
	logger, err := newLogger(io.Discard, "error", "text")
	if err != nil {
		t.Fatal(err)
	}
	const hostile = `/metrics"><script>alert(1)</script>`
	srv := newServer(options{listenAddr: "127.0.0.1:0", telemetryPath: hostile},
		config.Config{Address: "h", Username: "u", Password: "p"},
		prometheus.NewRegistry(), logger)

	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if strings.Contains(rec.Body.String(), "<script>") {
		t.Errorf("the landing page emitted raw markup: %s", rec.Body.String())
	}
}

func TestParseFlagsHelpIsNotAnError(t *testing.T) {
	var out bytes.Buffer
	_, err := parseFlags([]string{"-h"}, &out)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("err = %v, want flag.ErrHelp", err)
	}
	if err := run(context.Background(), []string{"-h"}, &out); err != nil {
		t.Errorf("run(-h) = %v, want nil", err)
	}
	if !strings.Contains(out.String(), "web.listen-address") {
		t.Errorf("help output does not document the flags: %s", out.String())
	}
}

func TestRunVersion(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"--version"}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out.String(), Version) {
		t.Errorf("version output = %q, want it to contain %q", out.String(), Version)
	}
}

func TestNewLogger(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		if _, err := newLogger(io.Discard, level, "text"); err != nil {
			t.Errorf("newLogger(%q) = %v", level, err)
		}
	}
	if _, err := newLogger(io.Discard, "info", "json"); err != nil {
		t.Errorf("json format rejected: %v", err)
	}
	if _, err := newLogger(io.Discard, "verbose", "text"); err == nil {
		t.Error("want an error for an unknown level")
	}
	if _, err := newLogger(io.Discard, "info", "xml"); err == nil {
		t.Error("want an error for an unknown format")
	}
}

func TestIsLoopback(t *testing.T) {
	tests := map[string]bool{
		"127.0.0.1:8080": true,
		"localhost:8080": true,
		"[::1]:8080":     true,
		"0.0.0.0:8080":   false,
		":8080":          false,
		"10.0.0.5:8080":  false,
	}
	for addr, want := range tests {
		if got := isLoopback(addr); got != want {
			t.Errorf("isLoopback(%q) = %t, want %t", addr, got, want)
		}
	}
}

func TestBasicAuth(t *testing.T) {
	guarded := basicAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "secret metrics")
	}), "prom", "pw")

	tests := []struct {
		name       string
		user, pass string
		setAuth    bool
		wantStatus int
	}{
		{"no credentials", "", "", false, http.StatusUnauthorized},
		{"wrong password", "prom", "nope", true, http.StatusUnauthorized},
		{"wrong user", "nope", "pw", true, http.StatusUnauthorized},
		{"empty credentials", "", "", true, http.StatusUnauthorized},
		{"correct", "prom", "pw", true, http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			if tc.setAuth {
				req.SetBasicAuth(tc.user, tc.pass)
			}
			rec := httptest.NewRecorder()
			guarded.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusUnauthorized {
				if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
					t.Errorf("WWW-Authenticate = %q, want a Basic challenge", got)
				}
				if strings.Contains(rec.Body.String(), "secret metrics") {
					t.Error("the guarded handler ran anyway")
				}
			}
		})
	}
}

// fakeSwitch serves the two pages the exporter needs.
func fakeSwitch(t *testing.T) string {
	t.Helper()
	const stats = `<html><body><table>
<tr><td>Port</td><td>State</td><td>Link Status</td><td>TxGoodPkt</td><td>TxBadPkt</td><td>RxGoodPkt</td><td>RxBadPkt</td></tr>
<tr><td>Port 1</td><td>Enable</td><td>Link Up</td><td>4242</td><td>0</td><td>2424</td><td>1</td></tr>
<tr><td>Port 2</td><td>Disable</td><td>Link Down</td><td>0</td><td>0</td><td>0</td><td>0</td></tr>
</table></body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, stats)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// freeAddr reserves a loopback port and releases it again.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("releasing the port: %v", err)
	}
	return addr
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

func clearEnv(t *testing.T) {
	t.Helper()
	for _, env := range []string{
		config.EnvAddress, config.EnvUsername, config.EnvPassword,
		config.EnvWebAuthUsername, config.EnvWebAuthPassword,
	} {
		t.Setenv(env, "")
	}
}

// testClient is a fresh client per call with keep-alives disabled. Sharing
// http.DefaultClient across tests pools connections, and freeAddr can hand out a
// port a previous test used, so a stale pooled connection would occasionally be
// reused against a different server.
func testClient() *http.Client {
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
}

// waitReady blocks until the exporter answers its liveness probe.
func waitReady(t *testing.T, listenAddr string, done <-chan error) {
	t.Helper()
	client := testClient()
	deadline := time.Now().Add(10 * time.Second)

	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
			"http://"+listenAddr+healthPath, nil)
		if err != nil {
			t.Fatalf("building probe request: %v", err)
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		select {
		case err := <-done:
			t.Fatalf("run exited early: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatal("the exporter never became ready")
}

// startExporter runs the exporter until the test finishes.
func startExporter(t *testing.T, configPath, listenAddr string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{
			"-c", configPath,
			"--web.listen-address", listenAddr,
			"--log.level", "error",
		}, io.Discard)
	}()

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("run returned %v, want a clean shutdown", err)
			}
		case <-time.After(shutdownTimeout + 5*time.Second):
			t.Error("run did not return after the context was cancelled")
		}
	})

	waitReady(t, listenAddr, done)
}

func get(t *testing.T, url string, setAuth func(*http.Request)) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	if setAuth != nil {
		setAuth(req)
	}
	resp, err := testClient().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("reading %s: %v", url, err)
	}
	return resp.StatusCode, string(body)
}

func TestRunServesMetricsEndToEnd(t *testing.T) {
	clearEnv(t)
	switchAddr := fakeSwitch(t)
	listenAddr := freeAddr(t)
	configPath := writeConfig(t, fmt.Sprintf(
		"address: %q\nusername: admin\npassword: admin\npoll_rate_seconds: 0\ntimeout_seconds: 2\npoe: false\n",
		switchAddr))

	startExporter(t, configPath, listenAddr)
	base := "http://" + listenAddr

	status, body := get(t, base+"/metrics", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /metrics = %d\n%s", status, body)
	}
	wantLines := []string{
		`port_state{port="1"} 1`,
		`port_state{port="2"} 0`,
		`port_link_status{port="1"} 1`,
		`port_tx_good_pkt{port="1"} 4242`,
		`port_rx_bad_pkt{port="1"} 1`,
		`exporter_up 1`,
		`exporter_scrape_errors_total 0`,
		`exporter_build_info{`,
		// Registered explicitly on the dedicated registry.
		`go_goroutines`,
		// Contributed by promhttp.InstrumentMetricHandler.
		`promhttp_metric_handler_requests_in_flight`,
	}
	for _, want := range wantLines {
		if !strings.Contains(body, want) {
			t.Errorf("GET /metrics is missing %q", want)
		}
	}
	// PoE is disabled, so no PoE series may appear.
	if strings.Contains(body, "poe_port_watts") {
		t.Error("PoE metrics were exposed although PoE is disabled")
	}

	// The health endpoint must answer without touching the switch.
	if status, body := get(t, base+"/healthz", nil); status != http.StatusOK || !strings.Contains(body, "ok") {
		t.Errorf("GET /healthz = %d %q", status, body)
	}
	if status, body := get(t, base+"/", nil); status != http.StatusOK || !strings.Contains(body, "/metrics") {
		t.Errorf("GET / = %d %q", status, body)
	}
	if status, _ := get(t, base+"/nope", nil); status != http.StatusNotFound {
		t.Errorf("GET /nope = %d, want 404", status)
	}
}

// A switch that is unreachable must still produce a scrapeable endpoint, with
// exporter_up at zero.
func TestRunReportsUnreachableSwitch(t *testing.T) {
	clearEnv(t)
	listenAddr := freeAddr(t)
	// Reserve and release a port so nothing is listening on it.
	deadSwitch := freeAddr(t)
	configPath := writeConfig(t, fmt.Sprintf(
		"address: %q\nusername: admin\npassword: admin\npoll_rate_seconds: 0\ntimeout_seconds: 1\n",
		deadSwitch))

	startExporter(t, configPath, listenAddr)

	status, body := get(t, "http://"+listenAddr+"/metrics", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /metrics = %d\n%s", status, body)
	}
	if !strings.Contains(body, "exporter_up 0") {
		t.Error("want exporter_up 0 for an unreachable switch")
	}
	if !strings.Contains(body, "exporter_scrape_errors_total 1") {
		t.Error("want the scrape error to be counted")
	}
	if strings.Contains(body, "port_state{") {
		t.Error("port metrics were exposed although the switch is unreachable")
	}
}

func TestRunEnforcesBasicAuth(t *testing.T) {
	clearEnv(t)
	switchAddr := fakeSwitch(t)
	listenAddr := freeAddr(t)
	configPath := writeConfig(t, fmt.Sprintf(
		"address: %q\nusername: admin\npassword: admin\ntimeout_seconds: 2\n"+
			"web:\n  auth_username: prom\n  auth_password: pw\n", switchAddr))

	startExporter(t, configPath, listenAddr)
	base := "http://" + listenAddr

	if status, _ := get(t, base+"/metrics", nil); status != http.StatusUnauthorized {
		t.Errorf("unauthenticated GET /metrics = %d, want 401", status)
	}
	status, body := get(t, base+"/metrics", func(r *http.Request) { r.SetBasicAuth("prom", "pw") })
	if status != http.StatusOK {
		t.Fatalf("authenticated GET /metrics = %d", status)
	}
	if !strings.Contains(body, "exporter_up 1") {
		t.Error("want exporter_up 1")
	}
	// Liveness stays open so container health checks keep working.
	if status, _ := get(t, base+"/healthz", nil); status != http.StatusOK {
		t.Errorf("GET /healthz = %d, want it to stay unauthenticated", status)
	}
}

// Shutdown must not wait for a wedged device. The lifetime context reaches the
// switch client, so cancelling it aborts the in-flight poll and lets the server
// drain.
//
// The device timeout is deliberately far larger than shutdownTimeout: if the
// in-flight poll were not aborted, srv.Shutdown would exceed its own deadline and
// run would return an error. That makes the assertion deterministic rather than
// dependent on wall-clock measurement.
func TestRunShutsDownWhileSwitchIsHung(t *testing.T) {
	clearEnv(t)

	release := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer func() {
		close(release)
		hung.Close()
	}()

	listenAddr := freeAddr(t)
	configPath := writeConfig(t, fmt.Sprintf(
		"address: %q\nusername: u\npassword: p\npoll_rate_seconds: 0\ntimeout_seconds: 120\n",
		strings.TrimPrefix(hung.URL, "http://")))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{
			"-c", configPath,
			"--web.listen-address", listenAddr,
			"--log.level", "error",
		}, io.Discard)
	}()
	waitReady(t, listenAddr, done)

	// Start a scrape that blocks inside the device request.
	scrapeDone := make(chan struct{})
	go func() {
		defer close(scrapeDone)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
			"http://"+listenAddr+"/metrics", nil)
		if err != nil {
			return
		}
		resp, err := testClient().Do(req)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	time.Sleep(300 * time.Millisecond)

	start := time.Now()
	cancel()
	select {
	case err := <-done:
		// A poll that was not aborted makes Shutdown blow its deadline.
		if err != nil {
			t.Fatalf("run returned %v, want a clean shutdown", err)
		}
	case <-time.After(shutdownTimeout + 10*time.Second):
		t.Fatal("run never returned while the switch was hung")
	}
	if elapsed := time.Since(start); elapsed >= shutdownTimeout {
		t.Errorf("shutdown took %v, which means it waited for the device", elapsed)
	}
	<-scrapeDone
}

func TestRunRejectsInvalidConfig(t *testing.T) {
	clearEnv(t)
	configPath := writeConfig(t, "address: \"http://192.168.1.1\"\nusername: u\npassword: p\n")
	err := run(context.Background(), []string{"-c", configPath}, io.Discard)
	if err == nil {
		t.Fatal("want an error for an address carrying a scheme")
	}
	if !strings.Contains(err.Error(), "bare host") {
		t.Errorf("err = %v, want it to explain the address format", err)
	}
}
