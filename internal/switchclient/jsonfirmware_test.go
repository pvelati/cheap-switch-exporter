package switchclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Tests for the JSON firmware family of issue #6. The protocol and the payload
// come from @jauling's report on a Goodtop ZX310S-8T2XS.

func loadJSON(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return data
}

func TestParseJSONPortStatistics(t *testing.T) {
	ports, err := parseJSONPortStatistics(loadJSON(t, "port_statistics.json"), discardLogger())
	if err != nil {
		t.Fatalf("parseJSONPortStatistics: %v", err)
	}
	if len(ports) != 10 {
		t.Fatalf("got %d ports, want 10", len(ports))
	}

	// Ports are top-level keys, so ordering has to be restored numerically.
	// Without that, Port_10 would sort before Port_2.
	want := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}
	for i, name := range want {
		if ports[i].Name != name {
			t.Errorf("ports[%d].Name = %q, want %q", i, ports[i].Name, name)
		}
	}

	first := ports[0]
	if !boolEq(first.Enabled, true) || !boolEq(first.LinkUp, true) {
		t.Errorf("port 1 = %s, want enabled and up", formatPort(first))
	}
	if !uintEq(first.TxGoodPkt, 45569130) || !uintEq(first.RxBadPkt, 412) {
		t.Errorf("port 1 counters = %s", formatPort(first))
	}
	if first.LinkSpeedMbps == nil || *first.LinkSpeedMbps != 1000 {
		t.Errorf("port 1 speed = %v, want 1000", first.LinkSpeedMbps)
	}

	// 2500MbpsFull, the reason this firmware is worth supporting.
	if ports[1].LinkSpeedMbps == nil || *ports[1].LinkSpeedMbps != 2500 {
		t.Errorf("port 2 speed = %v, want 2500", ports[1].LinkSpeedMbps)
	}
	// 10GbpsFull has to be converted to Mbps.
	if ports[8].LinkSpeedMbps == nil || *ports[8].LinkSpeedMbps != 10000 {
		t.Errorf("port 9 speed = %v, want 10000", ports[8].LinkSpeedMbps)
	}
	// A down port reports no speed at all rather than zero.
	if ports[2].LinkSpeedMbps != nil {
		t.Errorf("port 3 speed = %d, want no sample for a down port", *ports[2].LinkSpeedMbps)
	}
	if !boolEq(ports[3].Enabled, false) {
		t.Errorf("port 4 = %s, want disabled", formatPort(ports[3]))
	}
	// A dash must produce no counter, exactly as in the HTML family.
	if ports[9].TxBadPkt != nil {
		t.Errorf("port 10 TxBadPkt = %d, want no sample", *ports[9].TxBadPkt)
	}
}

func TestParseJSONLinkStatus(t *testing.T) {
	tests := []struct {
		in    string
		up    *bool
		speed *uint64
	}{
		{"1000MbpsFull", ptr(true), ptr(uint64(1000))},
		{"2500MbpsFull", ptr(true), ptr(uint64(2500))},
		{"100MbpsHalf", ptr(true), ptr(uint64(100))},
		{"10GbpsFull", ptr(true), ptr(uint64(10000))},
		{"Down", ptr(false), nil},
		{"", ptr(false), nil},
		{"-", ptr(false), nil},
		// The HTML family spellings still work through the fallback.
		{"Link Up", ptr(true), nil},
		{"Link Down", ptr(false), nil},
		// Something new stays unknown rather than being guessed at.
		{"Negotiating", nil, nil},
	}
	for _, tc := range tests {
		up, speed := parseJSONLinkStatus(tc.in)
		switch {
		case tc.up == nil && up != nil:
			t.Errorf("parseJSONLinkStatus(%q) up = %t, want nil", tc.in, *up)
		case tc.up != nil && !boolEq(up, *tc.up):
			t.Errorf("parseJSONLinkStatus(%q) up = %v, want %t", tc.in, up, *tc.up)
		}
		switch {
		case tc.speed == nil && speed != nil:
			t.Errorf("parseJSONLinkStatus(%q) speed = %d, want nil", tc.in, *speed)
		case tc.speed != nil && (speed == nil || *speed != *tc.speed):
			t.Errorf("parseJSONLinkStatus(%q) speed = %v, want %d", tc.in, speed, *tc.speed)
		}
	}
}

// A login page instead of JSON is the "not authorised yet" case and must be
// reported as missing data so the caller authorises and retries.
func TestParseJSONRejectsNonJSON(t *testing.T) {
	_, err := parseJSONPortStatistics([]byte("<html><body>Login</body></html>"), discardLogger())
	if !errors.Is(err, ErrNoData) {
		t.Fatalf("err = %v, want ErrNoData", err)
	}
	// Valid JSON with no port entries is equally useless.
	if _, err := parseJSONPortStatistics([]byte(`{"PortNum":"0"}`), discardLogger()); !errors.Is(err, ErrNoData) {
		t.Fatalf("err = %v, want ErrNoData", err)
	}
}

// jsonSwitch emulates the device: statistics only after /authorize.
type jsonSwitch struct {
	mu         sync.Mutex
	authorised bool
	authCalls  int
	statsCalls int
	lastQuery  url.Values
}

func (s *jsonSwitch) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	stats := loadJSON(t, "port_statistics.json")

	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()

		switch r.URL.Path {
		case pathAuthorize:
			s.authCalls++
			s.lastQuery = r.URL.Query()
			if r.URL.Query().Get("loginusr") == md5Hex(testUser) &&
				r.URL.Query().Get("loginpwd") == md5Hex(testPass) {
				s.authorised = true
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"result":"ok"}`))
				return
			}
			_, _ = w.Write([]byte("<html>Login</html>"))
		case pathPortStatsJSON:
			s.statsCalls++
			if !s.authorised {
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte("<html>Login</html>"))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(stats)
		default:
			http.NotFound(w, r)
		}
	}
}

func (s *jsonSwitch) counts() (auth, stats int, q url.Values) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authCalls, s.statsCalls, s.lastQuery
}

func newJSONClientFor(t *testing.T, handler http.HandlerFunc) *JSONClient {
	t.Helper()
	srv := newTestServer(t, handler)
	return NewJSON(Options{
		Address:  strings.TrimPrefix(srv, "http://"),
		Username: testUser,
		Password: testPass,
		Timeout:  5 * time.Second,
		Logger:   discardLogger(),
	})
}

func TestJSONClientAuthorisesThenReadsStatistics(t *testing.T) {
	sw := &jsonSwitch{}
	client := newJSONClientFor(t, sw.handler(t))

	ports, err := client.PortStatistics(context.Background())
	if err != nil {
		t.Fatalf("PortStatistics: %v", err)
	}
	if len(ports) != 10 {
		t.Fatalf("got %d ports, want 10", len(ports))
	}

	auth, stats, query := sw.counts()
	if auth != 1 {
		t.Errorf("authorised %d times, want 1", auth)
	}
	if stats != 2 {
		t.Errorf("read the statistics %d times, want 2 (before and after authorising)", stats)
	}
	// The credentials are hashed separately, unlike the HTML family.
	if got := query.Get("loginusr"); got != md5Hex(testUser) {
		t.Errorf("loginusr = %q, want md5 of the username alone", got)
	}
	if got := query.Get("loginpwd"); got != md5Hex(testPass) {
		t.Errorf("loginpwd = %q, want md5 of the password alone", got)
	}
	if query.Get("loginusr") == md5Hex(testUser+testPass) {
		t.Error("the JSON firmware must not receive the combined token")
	}

	// The session is reused.
	if _, err := client.PortStatistics(context.Background()); err != nil {
		t.Fatalf("second PortStatistics: %v", err)
	}
	if auth, _, _ := sw.counts(); auth != 1 {
		t.Errorf("authorised %d times across two scrapes, want 1", auth)
	}
}

func TestJSONClientReportsBadCredentials(t *testing.T) {
	sw := &jsonSwitch{}
	client := NewJSON(Options{
		Address:  strings.TrimPrefix(newTestServer(t, sw.handler(t)), "http://"),
		Username: testUser,
		Password: "wrong",
		Timeout:  5 * time.Second,
		Logger:   discardLogger(),
	})

	_, err := client.PortStatistics(context.Background())
	if !errors.Is(err, ErrNoData) {
		t.Fatalf("err = %v, want it to wrap ErrNoData", err)
	}
	if auth, _, _ := sw.counts(); auth != 1 {
		t.Errorf("authorised %d times, want exactly 1", auth)
	}
}

func TestJSONClientRejectsErrorStatus(t *testing.T) {
	client := newJSONClientFor(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	})
	_, err := client.PortStatistics(context.Background())
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "unexpected status") {
		t.Errorf("err = %v, want it to mention the status", err)
	}
}

// No PoE endpoint has been reported for this family, so the methods must say so
// rather than silently returning nothing.
func TestJSONClientReportsPoEUnsupported(t *testing.T) {
	client := newJSONClientFor(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	if _, err := client.PoEPorts(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Errorf("PoEPorts err = %v, want ErrUnsupported", err)
	}
	if _, err := client.PoESystem(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Errorf("PoESystem err = %v, want ErrUnsupported", err)
	}
}
