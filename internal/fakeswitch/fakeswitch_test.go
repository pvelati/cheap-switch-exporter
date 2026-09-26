package fakeswitch

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests check the test double itself. A fake that quietly stops emulating
// a firmware would make the acceptance suite pass for the wrong reason.

func serve(t *testing.T, opts Options) (*httptest.Server, *Switch) {
	t.Helper()
	sw := New(opts)
	srv := httptest.NewServer(sw)
	t.Cleanup(srv.Close)
	return srv, sw
}

// fetch performs a GET carrying the synthetic credential cookie, the way the
// exporter does before it has a session.
func fetch(t *testing.T, srv *httptest.Server, path string, mutate func(*http.Request)) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil) //nolint:noctx // test helper
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: cookieName, Value: md5Hex("admin" + "admin")})
	req.Header.Set("Referer", srv.URL+"/menu.cgi")
	if mutate != nil {
		mutate(req)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(body)
}

func login(t *testing.T, srv *httptest.Server, user, pass string) *http.Cookie {
	t.Helper()
	form := strings.NewReader("username=" + user + "&password=" + pass + "&language=EN")
	req, err := http.NewRequest(http.MethodPost, srv.URL+pathLogin, form) //nolint:noctx // test helper
	if err != nil {
		t.Fatalf("building login: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", pathLogin, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	return nil
}

// countRows counts data rows, excluding the <td> header row.
func countRows(body string) int {
	n := strings.Count(body, "<tr>")
	if n > 0 {
		n-- // the header row
	}
	return n
}

func TestEveryProfileIsServable(t *testing.T) {
	for _, p := range Profiles() {
		t.Run(string(p), func(t *testing.T) {
			srv, _ := serve(t, Options{Profile: p, Delay: 10 * time.Millisecond})
			// The JSON family serves a different endpoint entirely.
			path := pathPortStats
			if p.UsesJSON() {
				path = pathStatsJSON
			}
			status, body := fetch(t, srv, path, nil)

			if p == ProfileUnauthorized {
				if status != http.StatusUnauthorized {
					t.Fatalf("status = %d, want 401", status)
				}
				return
			}
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200", status)
			}
			if body == "" {
				t.Fatal("empty body")
			}
		})
	}
}

func TestStandardProfileServesPortTable(t *testing.T) {
	srv, sw := serve(t, Options{Profile: ProfileStandard, Ports: 8, Seed: 1})

	status, body := fetch(t, srv, pathPortStats, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if got := countRows(body); got != 8 {
		t.Errorf("got %d data rows, want 8", got)
	}
	for _, want := range []string{"<td>Port</td>", "<td>Enable</td>", "<td>Link Up</td>", "<td>Link Down</td>"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	// Bare port identifiers, no "Port N" prefix on this profile.
	if strings.Contains(body, "<td>Port 1</td>") {
		t.Error("the standard profile should report bare port numbers")
	}
	if got := sw.Counts().PortStats; got != 1 {
		t.Errorf("PortStats count = %d, want 1", got)
	}
}

// Without a valid cookie the device must answer the login page at HTTP 200,
// which is the behaviour that makes a bad password hard to spot.
func TestStandardProfileRequiresTheCredentialCookie(t *testing.T) {
	srv, _ := serve(t, Options{Profile: ProfileStandard})

	req, err := http.NewRequest(http.MethodGet, srv.URL+pathPortStats, nil) //nolint:noctx // test helper
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 even without a session", resp.StatusCode)
	}
	if !strings.Contains(string(body), "login.cgi") {
		t.Error("want the login page")
	}
}

func TestQuirksProfileEmitsTheOddities(t *testing.T) {
	srv, _ := serve(t, Options{Profile: ProfileQuirks, Ports: 4, Seed: 2})
	_, body := fetch(t, srv, pathPortStats, nil)

	for _, want := range []string{
		"<td>Port 1</td>", // prefixed names
		"&nbsp;",          // non-breaking space after the state
		"<td>-</td>",      // a dash instead of a counter
		"vlan.cgi",        // decoy navigation table
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing quirk %q", want)
		}
	}
	// The navigation table adds one row, so there is one more <tr> than ports.
	if got := countRows(body); got != 5 {
		t.Errorf("got %d rows, want 4 ports plus the decoy row", got)
	}
}

func TestKeepLinkProfileNeedsRefererAndPrefixesCells(t *testing.T) {
	srv, _ := serve(t, Options{Profile: ProfileKeepLink, Ports: 2})

	_, withReferer := fetch(t, srv, pathPortStats, nil)
	if !strings.Contains(withReferer, "<td>0-Enable</td>") {
		t.Errorf("cells are not prefixed with 0-:\n%s", withReferer)
	}

	_, without := fetch(t, srv, pathPortStats, func(r *http.Request) {
		r.Header.Del("Referer")
	})
	if strings.Contains(without, "<td>") {
		t.Error("want an empty page when the Referer is absent")
	}
}

// Issue #19: data only after an explicit login.
func TestSessionProfileNeedsLogin(t *testing.T) {
	srv, sw := serve(t, Options{Profile: ProfileSession, Ports: 3})

	if _, body := fetch(t, srv, pathPortStats, nil); !strings.Contains(body, "login.cgi") {
		t.Fatal("want the login page before authenticating")
	}
	if c := login(t, srv, "admin", "admin"); c != nil {
		t.Error("this profile should not hand out its own cookie")
	}
	_, body := fetch(t, srv, pathPortStats, nil)
	if got := countRows(body); got != 3 {
		t.Errorf("got %d data rows after login, want 3", got)
	}
	if got := sw.Counts().Login; got != 1 {
		t.Errorf("Login count = %d, want 1", got)
	}
}

// Wrong credentials must not create a session.
func TestSessionProfileRejectsWrongCredentials(t *testing.T) {
	srv, _ := serve(t, Options{Profile: ProfileSession, Username: "admin", Password: "right"})

	login(t, srv, "admin", "wrong")
	if _, body := fetch(t, srv, pathPortStats, nil); !strings.Contains(body, "login.cgi") {
		t.Error("a failed login must not grant access")
	}
	login(t, srv, "admin", "right")
	if _, body := fetch(t, srv, pathPortStats, nil); strings.Contains(body, "login.cgi") {
		t.Error("a successful login must grant access")
	}
}

// Issue #8: the device issues its own cookie and ignores the synthetic one.
func TestBinardatProfileIssuesItsOwnCookie(t *testing.T) {
	srv, _ := serve(t, Options{Profile: ProfileBinardat, Ports: 2})

	// The synthetic cookie alone is not enough.
	if _, body := fetch(t, srv, pathPortStats, nil); !strings.Contains(body, "login.cgi") {
		t.Error("the synthetic cookie must be rejected by this profile")
	}

	cookie := login(t, srv, "admin", "admin")
	if cookie == nil {
		t.Fatal("the device did not set a session cookie")
	}
	if cookie.Value != deviceSessionValue {
		t.Errorf("cookie = %q, want %q", cookie.Value, deviceSessionValue)
	}

	_, body := fetch(t, srv, pathPortStats, func(r *http.Request) {
		r.Header.Set("Cookie", cookieName+"="+cookie.Value)
	})
	if got := countRows(body); got != 2 {
		t.Errorf("got %d data rows with the device cookie, want 2", got)
	}
}

func TestPoEProfileServesPoEPages(t *testing.T) {
	srv, sw := serve(t, Options{Profile: ProfilePoE, Ports: 6, Seed: 4})

	_, ports := fetch(t, srv, pathPoEPorts, nil)
	if !strings.Contains(ports, "<th>Port</th>") {
		t.Error("the PoE table should use a <th> header")
	}
	if !strings.Contains(ports, "Class") {
		t.Error("no PoE class reported")
	}
	if !strings.Contains(ports, "<td>-</td>") {
		t.Error("ports without a powered device should report dashes")
	}

	_, system := fetch(t, srv, pathPoESystem, nil)
	if !strings.Contains(system, `name="pse_con_pwr"`) {
		t.Errorf("no consumption input:\n%s", system)
	}
	if c := sw.Counts(); c.PoEPorts != 1 || c.PoESystem != 1 {
		t.Errorf("counts = %+v, want one request to each PoE page", c)
	}
}

// Non-PoE profiles must not answer the PoE pages, so the exporter's partial
// failure handling gets exercised.
func TestNonPoEProfilesDoNotServePoEPages(t *testing.T) {
	srv, _ := serve(t, Options{Profile: ProfileStandard})
	if status, _ := fetch(t, srv, pathPoEPorts, nil); status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", status)
	}
}

func TestGarbageProfileHasNoDataTable(t *testing.T) {
	srv, _ := serve(t, Options{Profile: ProfileGarbage})
	_, body := fetch(t, srv, pathPortStats, nil)
	if strings.Contains(body, "TxGoodPkt") {
		t.Error("the garbage profile must not serve a statistics table")
	}
}

func TestFlakyProfileAlternates(t *testing.T) {
	srv, _ := serve(t, Options{Profile: ProfileFlaky, Ports: 2})

	var served, refused int
	for i := 0; i < 6; i++ {
		_, body := fetch(t, srv, pathPortStats, nil)
		if strings.Contains(body, "login.cgi") {
			refused++
		} else {
			served++
		}
	}
	if served == 0 || refused == 0 {
		t.Errorf("served %d and refused %d, want both to happen", served, refused)
	}
}

func TestSlowProfileHonoursRequestCancellation(t *testing.T) {
	srv, _ := serve(t, Options{Profile: ProfileSlow, Delay: time.Minute})

	client := &http.Client{Timeout: 100 * time.Millisecond}
	req, err := http.NewRequest(http.MethodGet, srv.URL+pathPortStats, nil) //nolint:noctx // test helper
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := client.Do(req); err == nil { //nolint:bodyclose // the request never completes
		t.Fatal("want a timeout")
	}
	// The handler must return on cancellation, otherwise Close would block for a
	// minute and every test using this profile would be slow.
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("the request took %v", elapsed)
	}
}

// Counters must grow with elapsed time and never go backwards, so that rate()
// over the fake produces a usable graph.
func TestCountersAdvanceMonotonically(t *testing.T) {
	now := time.Now()
	sw := New(Options{
		Profile: ProfileStandard, Ports: 4, Seed: 1,
		Now: func() time.Time { return now },
	})
	srv := httptest.NewServer(sw)
	defer srv.Close()

	first := extractCounter(t, srv)
	now = now.Add(10 * time.Second)
	second := extractCounter(t, srv)
	now = now.Add(10 * time.Second)
	third := extractCounter(t, srv)

	if third <= second || second <= first {
		t.Errorf("counters did not advance: %d then %d then %d", first, second, third)
	}
}

// extractCounter reads the TxGoodPkt cell of the first data row.
func extractCounter(t *testing.T, srv *httptest.Server) uint64 {
	t.Helper()
	_, body := fetch(t, srv, pathPortStats, nil)

	rows := strings.Split(body, "<tr>")
	if len(rows) < 3 {
		t.Fatalf("no data rows in:\n%s", body)
	}
	cells := strings.Split(rows[2], "<td>")
	if len(cells) < 5 {
		t.Fatalf("row has too few cells: %q", rows[2])
	}
	value := strings.TrimSuffix(strings.TrimSpace(cells[4]), "</td>")

	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		t.Fatalf("cannot read counter %q: %v", value, err)
	}
	return n
}

func TestGroupInsertsThousandsSeparators(t *testing.T) {
	tests := map[uint64]string{
		0: "0", 1: "1", 999: "999", 1000: "1,000",
		279449: "279,449", 1234567: "1,234,567",
	}
	for in, want := range tests {
		if got := group(in); got != want {
			t.Errorf("group(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestProfilesAreUnique(t *testing.T) {
	seen := map[Profile]bool{}
	for _, p := range Profiles() {
		if seen[p] {
			t.Errorf("duplicate profile %q", p)
		}
		seen[p] = true
	}
	if len(seen) != len(Profiles()) {
		t.Error("Profiles() contains duplicates")
	}
	if !ProfilePoE.SupportsPoE() {
		t.Error("the poe profile should report PoE support")
	}
	if ProfileStandard.SupportsPoE() {
		t.Error("the standard profile should not report PoE support")
	}
}

// Issue #6: the JSON firmware authorises through /authorize with separately
// hashed credentials and then serves /port_statistics.json.
func TestMaxLinearProfileServesJSON(t *testing.T) {
	srv, sw := serve(t, Options{Profile: ProfileMaxLinear, Ports: 6, Seed: 3})

	// Before authorising, the device answers with its login page at HTTP 200.
	status, body := fetch(t, srv, pathStatsJSON, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if !strings.Contains(body, "login.cgi") {
		t.Errorf("want the login page before authorising, got:\n%s", body)
	}

	// The wrong hashes must not grant access.
	authorise(t, srv, md5Hex("admin"), md5Hex("wrong"))
	if _, body := fetch(t, srv, pathStatsJSON, nil); !strings.Contains(body, "login.cgi") {
		t.Error("bad credentials must not authorise")
	}

	authorise(t, srv, md5Hex("admin"), md5Hex("admin"))
	_, body = fetch(t, srv, pathStatsJSON, nil)
	if !strings.Contains(body, `"PortNum": "6"`) {
		t.Errorf("want 6 ports reported, got:\n%s", body)
	}
	for _, want := range []string{`"Port_1"`, `"Port_6"`, `"Port_Id"`, `"Link_Status"`, "MbpsFull"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	// Every value is a string on this firmware, including the counters.
	if !strings.Contains(body, `"TxGoodPkt": "`) {
		t.Error("counters should be quoted strings")
	}
	if c := sw.Counts(); c.Login != 2 || c.PortStats != 3 {
		t.Errorf("counts = %+v, want 2 authorisations and 3 statistics reads", c)
	}
}

// authorise calls /authorize with the given hashes.
func authorise(t *testing.T, srv *httptest.Server, usr, pwd string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+pathAuthorize+"?loginusr="+usr+"&loginpwd="+pwd, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", pathAuthorize, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
}
