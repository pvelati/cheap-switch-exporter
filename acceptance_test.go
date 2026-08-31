package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"cheap-switch-exporter/internal/fakeswitch"
)

// This file is the acceptance suite: it starts the real exporter against every
// emulated firmware and asserts on the exposition output, the way Prometheus
// would see it. It is the check to run after changing anything.

// startFake serves an emulated switch and returns its host:port.
func startFake(t *testing.T, opts fakeswitch.Options) (string, *fakeswitch.Switch) {
	t.Helper()
	sw := fakeswitch.New(opts)
	srv := httptest.NewServer(sw)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), sw
}

// scrape runs one scrape against a running exporter and returns the body.
func scrape(t *testing.T, listenAddr string) string {
	t.Helper()
	status, body := get(t, "http://"+listenAddr+"/metrics", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /metrics = %d\n%s", status, body)
	}
	return body
}

// sample extracts the value of a single exposition line.
func sample(t *testing.T, body, series string) (float64, bool) {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, series) {
			continue
		}
		rest := strings.TrimPrefix(line, series)
		// Guard against series being a prefix of a longer metric name.
		if rest != "" && !strings.HasPrefix(rest, " ") && !strings.HasPrefix(rest, "{") {
			continue
		}
		fields := strings.Fields(line)
		v, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			t.Fatalf("cannot parse %q: %v", line, err)
		}
		return v, true
	}
	return 0, false
}

func mustSample(t *testing.T, body, series string) float64 {
	t.Helper()
	v, ok := sample(t, body, series)
	if !ok {
		t.Fatalf("series %q is absent from the exposition output", series)
	}
	return v
}

// TestAcceptanceProfiles runs the exporter against each emulated firmware.
func TestAcceptanceProfiles(t *testing.T) {
	tests := []struct {
		profile  fakeswitch.Profile
		poe      bool
		timeout  int
		wantUp   float64
		contains []string
		absent   []string
	}{
		{
			profile: fakeswitch.ProfileStandard, timeout: 2, wantUp: 1,
			contains: []string{
				`port_state{port="1"} 1`,
				`port_link_status{port="1"} 1`,
				`port_link_status{port="2"} 0`, // cabled but down
				`port_state{port="8"} 0`,       // administratively disabled
				`exporter_up 1`,
				`exporter_scrape_errors_total 0`,
			},
			absent: []string{"poe_port_watts", "poe_system_consumption_watts"},
		},
		{
			// "Port N" names, grouped numbers, non-breaking spaces, a dash for a
			// counter, and a decoy navigation table.
			profile: fakeswitch.ProfileQuirks, timeout: 2, wantUp: 1,
			contains: []string{
				`port_state{port="1"} 1`,
				`port_tx_good_pkt{port="1"}`,
				`exporter_up 1`,
			},
			absent: []string{
				`port_state{port="Port 1"}`, // the name must be normalised
				`port_tx_bad_pkt{port="8"}`, // the dash must yield no sample
			},
		},
		{
			profile: fakeswitch.ProfileKeepLink, timeout: 2, wantUp: 1,
			contains: []string{`port_state{port="1"} 1`, `exporter_up 1`},
			absent:   []string{`port_state{port="0-1"}`},
		},
		{
			// Issue #19: no data until the exporter logs in itself.
			profile: fakeswitch.ProfileSession, timeout: 2, wantUp: 1,
			contains: []string{`port_state{port="1"} 1`, `exporter_up 1`},
		},
		{
			// Issue #8: the device issues its own session cookie.
			profile: fakeswitch.ProfileBinardat, timeout: 2, wantUp: 1,
			contains: []string{`port_state{port="1"} 1`, `exporter_up 1`},
		},
		{
			profile: fakeswitch.ProfilePoE, poe: true, timeout: 2, wantUp: 1,
			contains: []string{
				`port_state{port="1"} 1`,
				`poe_port_state{port="1"} 1`,
				`poe_port_power_on{port="1"} 1`,
				`poe_port_watts{port="1"}`,
				`poe_port_type{port="1"}`,
				`poe_system_consumption_watts`,
				`exporter_up 1`,
			},
		},
		{
			// An unsupported firmware must fail loudly, not report zeros.
			profile: fakeswitch.ProfileGarbage, timeout: 2, wantUp: 0,
			contains: []string{`exporter_up 0`},
			absent:   []string{`port_state{`},
		},
		{
			profile: fakeswitch.ProfileUnauthorized, timeout: 2, wantUp: 0,
			contains: []string{`exporter_up 0`},
			absent:   []string{`port_state{`},
		},
		{
			// The device never answers within the timeout.
			profile: fakeswitch.ProfileSlow, timeout: 1, wantUp: 0,
			contains: []string{`exporter_up 0`},
			absent:   []string{`port_state{`},
		},
	}

	for _, tc := range tests {
		t.Run(string(tc.profile), func(t *testing.T) {
			clearEnv(t)
			switchAddr, _ := startFake(t, fakeswitch.Options{
				Profile: tc.profile,
				Seed:    1,
				Delay:   3 * time.Second,
			})
			listenAddr := freeAddr(t)
			configPath := writeConfig(t, fmt.Sprintf(
				"address: %q\nusername: admin\npassword: admin\n"+
					"poll_rate_seconds: 0\ntimeout_seconds: %d\npoe: %t\n",
				switchAddr, tc.timeout, tc.poe))

			startExporter(t, configPath, listenAddr)
			body := scrape(t, listenAddr)

			if got := mustSample(t, body, "exporter_up"); got != tc.wantUp {
				t.Errorf("exporter_up = %v, want %v", got, tc.wantUp)
			}
			for _, want := range tc.contains {
				if !strings.Contains(body, want) {
					t.Errorf("missing %q", want)
				}
			}
			for _, unwanted := range tc.absent {
				if strings.Contains(body, unwanted) {
					t.Errorf("unexpectedly present: %q", unwanted)
				}
			}
			// The exporter's own metrics must be there whatever the device did.
			for _, always := range []string{
				"exporter_up", "exporter_last_scrape_duration_seconds",
				"exporter_scrape_errors_total", "exporter_build_info",
			} {
				if _, ok := sample(t, body, always); !ok {
					t.Errorf("meta metric %q is missing", always)
				}
			}
		})
	}
}

// Counters must only ever go up: a decreasing counter is read as a device reset
// and shows up as a spike in rate().
func TestAcceptanceCountersAreMonotonic(t *testing.T) {
	clearEnv(t)
	switchAddr, _ := startFake(t, fakeswitch.Options{Profile: fakeswitch.ProfileStandard, Seed: 7})
	listenAddr := freeAddr(t)
	configPath := writeConfig(t, fmt.Sprintf(
		"address: %q\nusername: admin\npassword: admin\npoll_rate_seconds: 0\ntimeout_seconds: 2\n",
		switchAddr))
	startExporter(t, configPath, listenAddr)

	const series = `port_tx_good_pkt{port="1"}`
	previous := mustSample(t, scrape(t, listenAddr), series)
	for i := 0; i < 3; i++ {
		time.Sleep(150 * time.Millisecond)
		current := mustSample(t, scrape(t, listenAddr), series)
		if current < previous {
			t.Fatalf("%s went backwards: %v then %v", series, previous, current)
		}
		previous = current
	}
	if previous == 0 {
		t.Error("the fake switch reported no traffic at all")
	}
}

// A device that drops sessions under load must not produce gaps: the exporter
// re-authenticates and retries within the same scrape.
func TestAcceptanceRecoversFromDroppedSessions(t *testing.T) {
	clearEnv(t)
	switchAddr, sw := startFake(t, fakeswitch.Options{Profile: fakeswitch.ProfileFlaky, Seed: 3})
	listenAddr := freeAddr(t)
	configPath := writeConfig(t, fmt.Sprintf(
		"address: %q\nusername: admin\npassword: admin\npoll_rate_seconds: 0\ntimeout_seconds: 2\n",
		switchAddr))
	startExporter(t, configPath, listenAddr)

	for i := 0; i < 6; i++ {
		body := scrape(t, listenAddr)
		if got := mustSample(t, body, "exporter_up"); got != 1 {
			t.Fatalf("scrape %d: exporter_up = %v, want 1 despite the dropped session", i, got)
		}
	}
	if got := sw.Counts().Login; got == 0 {
		t.Error("the exporter never authenticated against a session-dropping device")
	}
}

// Wrong credentials must be reported, not silently turned into an empty scrape.
func TestAcceptanceWrongCredentials(t *testing.T) {
	clearEnv(t)
	switchAddr, _ := startFake(t, fakeswitch.Options{
		Profile: fakeswitch.ProfileSession, Username: "admin", Password: "correct-horse",
	})
	listenAddr := freeAddr(t)
	configPath := writeConfig(t, fmt.Sprintf(
		"address: %q\nusername: admin\npassword: wrong\npoll_rate_seconds: 0\ntimeout_seconds: 2\n",
		switchAddr))
	startExporter(t, configPath, listenAddr)

	body := scrape(t, listenAddr)
	if got := mustSample(t, body, "exporter_up"); got != 0 {
		t.Errorf("exporter_up = %v, want 0 for wrong credentials", got)
	}
	if got := mustSample(t, body, "exporter_scrape_errors_total"); got < 1 {
		t.Errorf("exporter_scrape_errors_total = %v, want at least 1", got)
	}
	if strings.Contains(body, "port_state{") {
		t.Error("port metrics were exposed although authentication failed")
	}
}

// Counters must be typed as counters no matter which exposition format the
// scraper negotiates. OpenMetrics requires counter series to be named *_total
// and downgrades anything else to "unknown", so the exporter does not offer it.
func TestAcceptanceCounterTypeSurvivesFormatNegotiation(t *testing.T) {
	clearEnv(t)
	switchAddr, _ := startFake(t, fakeswitch.Options{Profile: fakeswitch.ProfilePoE, Seed: 5})
	listenAddr := freeAddr(t)
	configPath := writeConfig(t, fmt.Sprintf(
		"address: %q\nusername: admin\npassword: admin\npoll_rate_seconds: 0\ntimeout_seconds: 2\npoe: true\n",
		switchAddr))
	startExporter(t, configPath, listenAddr)

	// The first header is what Prometheus actually sends.
	for _, accept := range []string{
		"application/openmetrics-text;version=1.0.0,text/plain;version=0.0.4;q=0.5,*/*;q=0.1",
		"text/plain;version=0.0.4",
		"*/*",
		"",
	} {
		name := accept
		if name == "" {
			name = "(no Accept header)"
		}
		t.Run(name, func(t *testing.T) {
			status, body := get(t, "http://"+listenAddr+"/metrics", func(r *http.Request) {
				if accept != "" {
					r.Header.Set("Accept", accept)
				}
			})
			if status != http.StatusOK {
				t.Fatalf("status = %d", status)
			}
			for _, want := range []string{
				"# HELP port_state",
				"# TYPE port_state gauge",
				"# TYPE port_tx_good_pkt counter",
				"# TYPE port_rx_good_pkt counter",
				"# TYPE exporter_scrape_errors_total counter",
				"# TYPE poe_port_watts gauge",
			} {
				if !strings.Contains(body, want) {
					t.Errorf("missing %q", want)
				}
			}
			// A counter reported as untyped loses its metadata in Prometheus.
			for _, unwanted := range []string{
				"# TYPE port_tx_good_pkt unknown",
				"# TYPE port_rx_good_pkt unknown",
			} {
				if strings.Contains(body, unwanted) {
					t.Errorf("counter was downgraded: %q", unwanted)
				}
			}
		})
	}
}

// poll_rate_seconds is the guard that keeps a single-session device alive under
// redundant Prometheus servers, so it is worth asserting end to end.
func TestAcceptancePollRateShieldsTheDevice(t *testing.T) {
	clearEnv(t)
	switchAddr, sw := startFake(t, fakeswitch.Options{Profile: fakeswitch.ProfileStandard, Seed: 9})
	listenAddr := freeAddr(t)
	configPath := writeConfig(t, fmt.Sprintf(
		"address: %q\nusername: admin\npassword: admin\npoll_rate_seconds: 60\ntimeout_seconds: 2\n",
		switchAddr))
	startExporter(t, configPath, listenAddr)

	for i := 0; i < 5; i++ {
		scrape(t, listenAddr)
	}
	if got := sw.Counts().PortStats; got != 1 {
		t.Errorf("the device was polled %d times for 5 scrapes, want 1", got)
	}
}

// The landing page and the liveness probe must work without touching the device.
func TestAcceptanceEndpoints(t *testing.T) {
	clearEnv(t)
	switchAddr, sw := startFake(t, fakeswitch.Options{Profile: fakeswitch.ProfileStandard})
	listenAddr := freeAddr(t)
	configPath := writeConfig(t, fmt.Sprintf(
		"address: %q\nusername: admin\npassword: admin\ntimeout_seconds: 2\n", switchAddr))
	startExporter(t, configPath, listenAddr)

	base := "http://" + listenAddr
	if status, body := get(t, base+"/healthz", nil); status != http.StatusOK || !strings.Contains(body, "ok") {
		t.Errorf("GET /healthz = %d %q", status, body)
	}
	if status, body := get(t, base+"/", nil); status != http.StatusOK || !strings.Contains(body, "/metrics") {
		t.Errorf("GET / = %d %q", status, body)
	}
	if status, _ := get(t, base+"/nope", nil); status != http.StatusNotFound {
		t.Errorf("GET /nope = %d, want 404", status)
	}
	if got := sw.Counts().PortStats; got != 0 {
		t.Errorf("the device was polled %d times by non-metrics endpoints, want 0", got)
	}
}

// Concurrent scrapes, as a redundant pair of Prometheus servers would produce,
// must all succeed and must not corrupt the output. Run under -race.
func TestAcceptanceConcurrentScrapes(t *testing.T) {
	clearEnv(t)
	switchAddr, _ := startFake(t, fakeswitch.Options{Profile: fakeswitch.ProfileStandard, Seed: 11})
	listenAddr := freeAddr(t)
	configPath := writeConfig(t, fmt.Sprintf(
		"address: %q\nusername: admin\npassword: admin\npoll_rate_seconds: 1\ntimeout_seconds: 2\n",
		switchAddr))
	startExporter(t, configPath, listenAddr)

	results := make(chan string, 8)
	for i := 0; i < 8; i++ {
		go func() {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
				"http://"+listenAddr+"/metrics", nil)
			if err != nil {
				results <- "request build failed"
				return
			}
			resp, err := testClient().Do(req)
			if err != nil {
				results <- "request failed: " + err.Error()
				return
			}
			defer func() { _ = resp.Body.Close() }()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			if resp.StatusCode != http.StatusOK {
				results <- fmt.Sprintf("status %d", resp.StatusCode)
				return
			}
			if !strings.Contains(string(body), "exporter_up") {
				results <- "output missing exporter_up"
				return
			}
			results <- ""
		}()
	}
	for i := 0; i < 8; i++ {
		if problem := <-results; problem != "" {
			t.Errorf("concurrent scrape %d: %s", i, problem)
		}
	}
}
