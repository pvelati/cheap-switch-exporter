package switchclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testUser = "admin"
	testPass = "s3cret"
)

// recordedRequest captures what the fake switch received.
type recordedRequest struct {
	method  string
	query   url.Values
	cookie  string
	referer string
	form    url.Values
	body    string
}

// requestLog is written by the server goroutine and read by the test.
type requestLog struct {
	mu       sync.Mutex
	requests map[string]recordedRequest
}

func (l *requestLog) put(path string, rec recordedRequest) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.requests[path] = rec
}

func (l *requestLog) get(path string) (recordedRequest, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, ok := l.requests[path]
	return rec, ok
}

// newFakeSwitch serves the HTML fixtures and records the requests it received.
func newFakeSwitch(t *testing.T) (*Client, *requestLog) {
	t.Helper()
	log := &requestLog{requests: map[string]recordedRequest{}}

	fixtures := map[string]string{
		pathPortStats: "port_stats.html",
		pathPoEPorts:  "pse_port.html",
		pathPoESystem: "pse_system.html",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		form, _ := url.ParseQuery(string(body))
		rec := recordedRequest{
			method:  r.Method,
			query:   r.URL.Query(),
			referer: r.Header.Get("Referer"),
			form:    form,
			body:    string(body),
		}
		if c, err := r.Cookie("admin"); err == nil {
			rec.cookie = c.Value
		}
		log.put(r.URL.Path, rec)

		name, ok := fixtures[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)

	client := New(Options{
		Address:  strings.TrimPrefix(srv.URL, "http://"),
		Username: testUser,
		Password: testPass,
		Timeout:  5 * time.Second,
		Logger:   discardLogger(),
	})
	return client, log
}

func newClientFor(t *testing.T, handler http.HandlerFunc, timeout time.Duration) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return New(Options{
		Address:  strings.TrimPrefix(srv.URL, "http://"),
		Username: testUser,
		Password: testPass,
		Timeout:  timeout,
		Logger:   discardLogger(),
	})
}

func TestClientPortStatistics(t *testing.T) {
	client, log := newFakeSwitch(t)

	ports, err := client.PortStatistics(context.Background())
	if err != nil {
		t.Fatalf("PortStatistics: %v", err)
	}
	if len(ports) != 4 {
		t.Fatalf("got %d ports, want 4", len(ports))
	}

	req, ok := log.get(pathPortStats)
	if !ok {
		t.Fatal("the switch never received a request for the statistics page")
	}
	if req.method != http.MethodGet {
		t.Errorf("method = %s, want GET", req.method)
	}
	if got := req.query.Get("page"); got != "stats" {
		t.Errorf("page query = %q, want stats", got)
	}
	// The Referer is required by KeepLink firmwares.
	if !strings.HasSuffix(req.referer, pathReferer) {
		t.Errorf("Referer = %q, want it to end with %s", req.referer, pathReferer)
	}
	if req.cookie != md5Hex(testUser+testPass) {
		t.Errorf("admin cookie = %q, want the md5 credential token", req.cookie)
	}
	// The credential form travels in the body even though this is a GET.
	if req.form.Get("username") != testUser || req.form.Get("password") != testPass {
		t.Errorf("form = %q, want the credentials", req.body)
	}
	if req.form.Get("language") != "EN" {
		t.Errorf("language = %q, want EN", req.form.Get("language"))
	}
	if req.form.Get("Response") != md5Hex(testUser+testPass) {
		t.Errorf("Response = %q, want the md5 credential token", req.form.Get("Response"))
	}
}

func TestClientPoE(t *testing.T) {
	client, _ := newFakeSwitch(t)

	system, err := client.PoESystem(context.Background())
	if err != nil {
		t.Fatalf("PoESystem: %v", err)
	}
	if system.ConsumptionWatts != 28.7 {
		t.Errorf("ConsumptionWatts = %v, want 28.7", system.ConsumptionWatts)
	}

	ports, err := client.PoEPorts(context.Background())
	if err != nil {
		t.Fatalf("PoEPorts: %v", err)
	}
	if len(ports) != 4 {
		t.Fatalf("got %d PoE ports, want 4", len(ports))
	}
}

// A device answering 401, 403 or 500 used to be parsed as if it were a
// statistics page.
func TestClientRejectsNon200(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client := newClientFor(t, func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "nope", status)
			}, time.Second)

			_, err := client.PortStatistics(context.Background())
			if err == nil {
				t.Fatal("want an error for a non-200 response")
			}
			if !strings.Contains(err.Error(), "unexpected status") {
				t.Errorf("err = %v, want it to mention the status", err)
			}
		})
	}
}

// A redirect must not be followed: the credential cookie would be replayed to
// whatever host the device points at.
func TestClientDoesNotFollowRedirects(t *testing.T) {
	var mu sync.Mutex
	elsewhereHits := 0
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		elsewhereHits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer elsewhere.Close()

	client := newClientFor(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/steal", http.StatusFound)
	}, time.Second)

	if _, err := client.PortStatistics(context.Background()); err == nil {
		t.Fatal("want an error instead of a followed redirect")
	}
	mu.Lock()
	defer mu.Unlock()
	if elsewhereHits != 0 {
		t.Errorf("the redirect target was contacted %d times, want 0", elsewhereHits)
	}
}

func TestClientHonoursContextCancellation(t *testing.T) {
	release := make(chan struct{})
	client := newClientFor(t, func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}, time.Minute)
	// Registered after the server so that it runs first: cleanups are LIFO and
	// httptest.Server.Close waits for in-flight handlers.
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.PortStatistics(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestClientTimesOut(t *testing.T) {
	release := make(chan struct{})
	client := newClientFor(t, func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}, 50*time.Millisecond)
	t.Cleanup(func() { close(release) })

	start := time.Now()
	if _, err := client.PortStatistics(context.Background()); err == nil {
		t.Fatal("want a timeout error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the request took %v, the client timeout was not applied", elapsed)
	}
}

// The response is read through a limit reader, so an endlessly long page cannot
// exhaust the exporter's memory. Padding the page past the limit hides the table
// that follows it, which is what the assertion checks.
func TestClientLimitsResponseSize(t *testing.T) {
	client := newClientFor(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>")
		padding := strings.Repeat("<p>padding</p>", 4096)
		for written := 0; written <= maxResponseBytes; written += len(padding) {
			if _, err := io.WriteString(w, padding); err != nil {
				return
			}
		}
		_, _ = io.WriteString(w, `<table><tr><td>1</td><td>Enable</td><td>Link Up</td>`+
			`<td>1</td><td>0</td><td>1</td><td>0</td></tr></table></body></html>`)
	}, 30*time.Second)

	_, err := client.PortStatistics(context.Background())
	if !errors.Is(err, ErrNoData) {
		t.Fatalf("err = %v, want ErrNoData because the body was truncated", err)
	}
}

func TestMD5HexMatchesTheDeviceScheme(t *testing.T) {
	// Pinned so a refactor cannot silently change the authentication token.
	if got := md5Hex("adminadmin"); got != "f6fdffe48c908deb0f4c3bd36c032e72" {
		t.Fatalf("md5Hex(adminadmin) = %s", got)
	}
	// Issue #19 reported a case difference seen from PowerShell. Go's
	// hex.EncodeToString is lowercase, which is what the firmwares want, so no
	// case folding is needed here; this pins that.
	if got := md5Hex("Admin!Pass"); got != strings.ToLower(got) {
		t.Fatalf("md5Hex returned non-lowercase hex: %s", got)
	}
}

// sessionSwitch emulates the firmwares from issues #19 and #8: the statistics
// page only returns data while a session exists, and the login page is served
// with HTTP 200 when it does not.
type sessionSwitch struct {
	mu sync.Mutex
	// serverIssuedCookie makes the device hand out its own session cookie and
	// ignore the synthetic one, which is the Binardat behaviour of issue #8.
	serverIssuedCookie bool
	// acceptLogin allows simulating wrong credentials.
	acceptLogin bool
	// loggedIn is the session state for the synthetic-cookie firmware.
	loggedIn bool

	loginCalls int
	statsCalls int
}

const loginRedirectPage = `<html><body><script>
window.top.location.replace("/login.cgi");
</script></body></html>`

func (s *sessionSwitch) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	stats, err := os.ReadFile(filepath.Join("testdata", "port_stats.html"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "text/html")

		if r.URL.Path == pathLogin {
			s.loginCalls++
			if !s.acceptLogin {
				// Wrong credentials: the login page again, still HTTP 200.
				_, _ = io.WriteString(w, loginRedirectPage)
				return
			}
			if s.serverIssuedCookie {
				http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "server-session-42", Path: "/"})
			}
			s.loggedIn = true
			_, _ = io.WriteString(w, `<html><body><script>window.top.location.replace("/");</script></body></html>`)
			return
		}

		s.statsCalls++
		authorised := s.loggedIn
		if s.serverIssuedCookie {
			// Only the device's own cookie is accepted.
			c, err := r.Cookie(cookieName)
			authorised = err == nil && c.Value == "server-session-42"
		}
		if !authorised {
			_, _ = io.WriteString(w, loginRedirectPage)
			return
		}
		_, _ = w.Write(stats)
	}
}

func (s *sessionSwitch) counts() (login, stats int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loginCalls, s.statsCalls
}

// Issue #19: HC-SWTGW218AS only answered while a browser session happened to be
// open. The exporter must establish its own session instead.
func TestClientEstablishesSessionWhenLoggedOut(t *testing.T) {
	sw := &sessionSwitch{acceptLogin: true}
	client := newClientFor(t, sw.handler(t), 5*time.Second)

	ports, err := client.PortStatistics(context.Background())
	if err != nil {
		t.Fatalf("PortStatistics: %v", err)
	}
	if len(ports) != 4 {
		t.Fatalf("got %d ports, want 4", len(ports))
	}

	login, stats := sw.counts()
	if login != 1 {
		t.Errorf("logged in %d times, want exactly 1", login)
	}
	if stats != 2 {
		t.Errorf("fetched the stats page %d times, want 2 (before and after login)", stats)
	}

	// The session is reused: no further login on subsequent scrapes.
	if _, err := client.PortStatistics(context.Background()); err != nil {
		t.Fatalf("second PortStatistics: %v", err)
	}
	if login, _ := sw.counts(); login != 1 {
		t.Errorf("logged in %d times across two scrapes, want 1", login)
	}
}

// Issue #8: Binardat hands out its own cookie and ignores the synthetic one. The
// cookie jar has to replay whatever the device set.
func TestClientUsesDeviceIssuedSessionCookie(t *testing.T) {
	sw := &sessionSwitch{acceptLogin: true, serverIssuedCookie: true}
	client := newClientFor(t, sw.handler(t), 5*time.Second)

	ports, err := client.PortStatistics(context.Background())
	if err != nil {
		t.Fatalf("PortStatistics: %v", err)
	}
	if len(ports) != 4 {
		t.Fatalf("got %d ports, want 4", len(ports))
	}
	if login, _ := sw.counts(); login != 1 {
		t.Errorf("logged in %d times, want 1", login)
	}
}

// Wrong credentials must fail with a diagnosable error and must not retry
// forever: exactly one login attempt per page request.
func TestClientReportsFailedAuthentication(t *testing.T) {
	sw := &sessionSwitch{acceptLogin: false}
	client := newClientFor(t, sw.handler(t), 5*time.Second)

	_, err := client.PortStatistics(context.Background())
	if !errors.Is(err, ErrNoData) {
		t.Fatalf("err = %v, want it to wrap ErrNoData", err)
	}
	login, stats := sw.counts()
	if login != 1 {
		t.Errorf("logged in %d times, want exactly 1", login)
	}
	if stats != 2 {
		t.Errorf("fetched the stats page %d times, want 2", stats)
	}
}

// A firmware that needs no handshake must not be sent an extra login request:
// these devices serve one session at a time and every request costs.
func TestClientDoesNotLoginWhenNotNeeded(t *testing.T) {
	var mu sync.Mutex
	loginCalls := 0
	stats, err := os.ReadFile(filepath.Join("testdata", "port_stats.html"))
	if err != nil {
		t.Fatal(err)
	}

	client := newClientFor(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == pathLogin {
			mu.Lock()
			loginCalls++
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(stats)
	}, 5*time.Second)

	for i := 0; i < 3; i++ {
		if _, err := client.PortStatistics(context.Background()); err != nil {
			t.Fatalf("PortStatistics #%d: %v", i, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if loginCalls != 0 {
		t.Errorf("sent %d login requests to a firmware that needs none, want 0", loginCalls)
	}
}

// A transport level failure must not be mistaken for an expired session.
func TestClientDoesNotLoginOnTransportErrors(t *testing.T) {
	var mu sync.Mutex
	loginCalls := 0

	client := newClientFor(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == pathLogin {
			mu.Lock()
			loginCalls++
			mu.Unlock()
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	}, time.Second)

	if _, err := client.PortStatistics(context.Background()); err == nil {
		t.Fatal("want an error")
	}
	mu.Lock()
	defer mu.Unlock()
	if loginCalls != 0 {
		t.Errorf("attempted %d logins after an HTTP 500, want 0", loginCalls)
	}
}
