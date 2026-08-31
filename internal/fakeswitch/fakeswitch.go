// Package fakeswitch emulates the web interfaces of the switches this exporter
// supports, including their quirks and their failure modes.
//
// It backs both the acceptance tests and the standalone cmd/fakeswitch tool, so
// there is exactly one description of how each firmware behaves. Counters grow
// with elapsed time, which makes rate() over a fake device produce a plausible
// graph without any hardware.
package fakeswitch

import (
	"crypto/md5" //nolint:gosec // mirrors the device's authentication scheme
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Profile selects which firmware behaviour to emulate.
type Profile string

const (
	// ProfileStandard is the common RTL8373 style interface: a plain statistics
	// table, no session handshake. Horaco ZX-SWTGW218AS, Sodola SL-SWTG124AS.
	ProfileStandard Profile = "standard"
	// ProfileQuirks adds the formatting oddities seen in the wild: "Port N"
	// names, grouped numbers, dashes for missing counters, non-breaking spaces
	// and an unrelated navigation table before the data.
	ProfileQuirks Profile = "quirks"
	// ProfileKeepLink prefixes every cell with "0-" and returns an empty page
	// unless a Referer header is present. KeepLink KP-9000-9XHPML-X.
	ProfileKeepLink Profile = "keeplink"
	// ProfileSession only serves data after POST /login.cgi and answers with the
	// login page, at HTTP 200, when no session exists. Issue #19.
	ProfileSession Profile = "session"
	// ProfileBinardat hands out its own session cookie on login and ignores the
	// synthetic credential cookie entirely. Issue #8.
	ProfileBinardat Profile = "binardat"
	// ProfilePoE serves the PoE pages in addition to the port statistics.
	ProfilePoE Profile = "poe"
	// ProfileGarbage serves a page with no statistics table, standing in for an
	// unsupported firmware.
	ProfileGarbage Profile = "garbage"
	// ProfileUnauthorized rejects everything with HTTP 401.
	ProfileUnauthorized Profile = "unauthorized"
	// ProfileSlow delays every response past a typical timeout.
	ProfileSlow Profile = "slow"
	// ProfileFlaky alternates between serving data and serving the login page,
	// which is what a device that drops sessions under load looks like.
	ProfileFlaky Profile = "flaky"
)

// Profiles lists every emulated firmware.
func Profiles() []Profile {
	return []Profile{
		ProfileStandard, ProfileQuirks, ProfileKeepLink, ProfileSession,
		ProfileBinardat, ProfilePoE, ProfileGarbage, ProfileUnauthorized,
		ProfileSlow, ProfileFlaky,
	}
}

// SupportsPoE reports whether a profile serves the PoE pages.
func (p Profile) SupportsPoE() bool { return p == ProfilePoE }

// Paths served by the emulated interfaces.
const (
	pathPortStats = "/port.cgi"
	pathPoEPorts  = "/pse_port.cgi"
	pathPoESystem = "/pse_system.cgi"
	pathLogin     = "/login.cgi"
)

const (
	cookieName         = "admin"
	deviceSessionValue = "fake-session-cookie"
	defaultPorts       = 8
	defaultDelay       = 30 * time.Second
)

// Options configures a Switch.
type Options struct {
	Profile  Profile
	Ports    int
	Username string
	Password string
	// Delay is how long ProfileSlow waits before responding.
	Delay time.Duration
	// Seed makes the generated traffic reproducible.
	Seed int64
	// Now defaults to time.Now. Tests substitute it to control the counters.
	Now func() time.Time
}

// Counts records what the device was asked for, for use in assertions.
type Counts struct {
	Login     int
	PortStats int
	PoEPorts  int
	PoESystem int
	Rejected  int
}

// Switch is an emulated switch web interface. It implements http.Handler and is
// safe for concurrent use.
type Switch struct {
	profile  Profile
	username string
	password string
	token    string
	delay    time.Duration
	now      func() time.Time
	start    time.Time
	ports    []portModel

	mu       sync.Mutex
	counts   Counts
	loggedIn bool
	flakeOn  bool
}

type counterModel struct {
	base      uint64
	perSecond float64
}

func (c counterModel) at(elapsed float64) uint64 {
	if elapsed < 0 {
		elapsed = 0
	}
	return c.base + uint64(elapsed*c.perSecond)
}

type portModel struct {
	enabled bool
	linkUp  bool
	txGood  counterModel
	txBad   counterModel
	rxGood  counterModel
	rxBad   counterModel
	poe     poeModel
}

type poeModel struct {
	enabled bool
	powerOn bool
	// class is the IEEE power class, or -1 for "no powered device".
	class     int
	watts     float64
	voltage   float64
	currentMA float64
}

// New builds an emulated switch.
func New(opts Options) *Switch {
	if opts.Profile == "" {
		opts.Profile = ProfileStandard
	}
	if opts.Ports <= 0 {
		opts.Ports = defaultPorts
	}
	if opts.Username == "" {
		opts.Username = "admin"
	}
	if opts.Password == "" {
		opts.Password = "admin"
	}
	if opts.Delay <= 0 {
		opts.Delay = defaultDelay
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	s := &Switch{
		profile:  opts.Profile,
		username: opts.Username,
		password: opts.Password,
		token:    md5Hex(opts.Username + opts.Password),
		delay:    opts.Delay,
		now:      opts.Now,
	}
	s.start = s.now()
	s.ports = buildPorts(opts.Ports, opts.Seed)
	return s
}

// buildPorts generates a deterministic but varied set of ports: a couple down, a
// couple disabled, the rest passing traffic at different rates.
func buildPorts(n int, seed int64) []portModel {
	rng := rand.New(rand.NewSource(seed)) //nolint:gosec // reproducible test data, not security
	ports := make([]portModel, n)

	for i := range ports {
		enabled := i != n-1         // last port administratively disabled
		linkUp := enabled && i != 1 // second port cabled but down

		rate := 200 + rng.Float64()*4000
		p := portModel{
			enabled: enabled,
			linkUp:  linkUp,
			txGood:  counterModel{base: uint64(rng.Int63n(5_000_000)), perSecond: rate},
			txBad:   counterModel{base: uint64(rng.Int63n(10)), perSecond: rate / 100_000},
			rxGood:  counterModel{base: uint64(rng.Int63n(5_000_000)), perSecond: rate * 1.3},
			rxBad:   counterModel{base: uint64(rng.Int63n(20)), perSecond: rate / 50_000},
		}
		if !linkUp {
			p.txGood.perSecond, p.txBad.perSecond = 0, 0
			p.rxGood.perSecond, p.rxBad.perSecond = 0, 0
		}

		// PoE: powered devices on the first half, nothing attached on the rest.
		if i < n/2 && linkUp {
			class := 1 + rng.Intn(6)
			watts := 2 + rng.Float64()*20
			p.poe = poeModel{
				enabled: true, powerOn: true, class: class,
				watts: round1(watts), voltage: round1(52 + rng.Float64()),
				currentMA: round1(watts / 53 * 1000),
			}
		} else {
			p.poe = poeModel{enabled: enabled, powerOn: false, class: -1}
		}
		ports[i] = p
	}
	return ports
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }

// Counts returns what the device has been asked for.
func (s *Switch) Counts() Counts {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts
}

// ServeHTTP implements http.Handler.
func (s *Switch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.profile == ProfileSlow {
		select {
		case <-time.After(s.delay):
		case <-r.Context().Done():
			return
		}
	}

	if s.profile == ProfileUnauthorized {
		s.bump(func(c *Counts) { c.Rejected++ })
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if r.URL.Path == pathLogin {
		s.serveLogin(w, r)
		return
	}

	// KeepLink returns an empty page when the Referer is missing.
	if s.profile == ProfileKeepLink && r.Header.Get("Referer") == "" {
		s.write(w, "<html><body></body></html>")
		return
	}

	if !s.authorised(r) {
		s.write(w, loginPage)
		return
	}

	elapsed := s.now().Sub(s.start).Seconds()
	switch r.URL.Path {
	case pathPortStats:
		s.bump(func(c *Counts) { c.PortStats++ })
		if s.profile == ProfileGarbage {
			s.write(w, garbagePage)
			return
		}
		s.write(w, s.renderStats(elapsed))
	case pathPoEPorts:
		s.bump(func(c *Counts) { c.PoEPorts++ })
		if !s.profile.SupportsPoE() {
			http.NotFound(w, r)
			return
		}
		s.write(w, s.renderPoEPorts())
	case pathPoESystem:
		s.bump(func(c *Counts) { c.PoESystem++ })
		if !s.profile.SupportsPoE() {
			http.NotFound(w, r)
			return
		}
		s.write(w, s.renderPoESystem())
	default:
		http.NotFound(w, r)
	}
}

func (s *Switch) serveLogin(w http.ResponseWriter, r *http.Request) {
	s.bump(func(c *Counts) { c.Login++ })

	if err := r.ParseForm(); err == nil {
		user, pass := r.PostFormValue("username"), r.PostFormValue("password")
		if user != s.username || pass != s.password {
			// Wrong credentials: the login page again, still HTTP 200. This is
			// what makes a bad password hard to notice on these devices.
			s.write(w, loginPage)
			return
		}
	}

	if s.profile == ProfileBinardat {
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: deviceSessionValue, Path: "/"})
	}
	s.mu.Lock()
	s.loggedIn = true
	s.mu.Unlock()
	s.write(w, `<html><body><script>window.top.location.replace("/");</script></body></html>`)
}

// authorised applies the profile's notion of a valid session.
func (s *Switch) authorised(r *http.Request) bool {
	cookie, err := r.Cookie(cookieName)
	hasCookie := err == nil

	switch s.profile {
	case ProfileBinardat:
		// Only the cookie the device itself issued is accepted.
		return hasCookie && cookie.Value == deviceSessionValue
	case ProfileSession:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.loggedIn
	case ProfileFlaky:
		s.mu.Lock()
		defer s.mu.Unlock()
		s.flakeOn = !s.flakeOn
		return s.flakeOn
	default:
		// The synthetic credential cookie is enough.
		return hasCookie && cookie.Value == s.token
	}
}

func (s *Switch) bump(f func(*Counts)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(&s.counts)
}

func (s *Switch) write(w http.ResponseWriter, body string) {
	_, _ = w.Write([]byte(body))
}

const loginPage = `<html><head><title>Login</title></head><body>
<script>window.top.location.replace("/login.cgi");</script>
<form method="post" action="login.cgi">
<table>
<tr><td>Username</td><td><input type="text" name="username"></td></tr>
<tr><td>Password</td><td><input type="password" name="password"></td></tr>
</table></form></body></html>`

const garbagePage = `<html><head><title>Statistics</title></head><body>
<table><tr><td>This firmware renders its statistics with JavaScript.</td></tr></table>
</body></html>`

// renderStats builds the port statistics page for the current profile.
func (s *Switch) renderStats(elapsed float64) string {
	var b strings.Builder
	b.WriteString("<html><head><title>Port Statistics</title></head><body>\n")

	if s.profile == ProfileQuirks {
		// An unrelated navigation table, which must not be read as data.
		b.WriteString(`<table><tr><td><a href="port.cgi">Port</a></td>` +
			`<td><a href="vlan.cgi">VLAN</a></td></tr></table>` + "\n")
	}

	b.WriteString("<table border=\"1\">\n")
	// These firmwares mark the header row with <td>, not <th>.
	b.WriteString(s.row("Port", "State", "Link Status",
		"TxGoodPkt", "TxBadPkt", "RxGoodPkt", "RxBadPkt"))

	for i, p := range s.ports {
		name := fmt.Sprintf("%d", i+1)
		state := "Disable"
		if p.enabled {
			state = "Enable"
		}
		link := "Link Down"
		if p.linkUp {
			link = "Link Up"
		}
		txGood := fmt.Sprintf("%d", p.txGood.at(elapsed))
		txBad := fmt.Sprintf("%d", p.txBad.at(elapsed))
		rxGood := fmt.Sprintf("%d", p.rxGood.at(elapsed))
		rxBad := fmt.Sprintf("%d", p.rxBad.at(elapsed))

		if s.profile == ProfileQuirks {
			name = "Port " + name
			state += "&nbsp;"
			rxGood = group(p.rxGood.at(elapsed))
			if i == len(s.ports)-1 {
				// Some firmwares print a dash instead of a counter. The exporter
				// must omit the sample rather than report zero.
				txBad = "-"
			}
		}
		b.WriteString(s.row(name, state, link, txGood, txBad, rxGood, rxBad))
	}

	b.WriteString("</table>\n</body></html>\n")
	return b.String()
}

func (s *Switch) renderPoEPorts() string {
	var b strings.Builder
	b.WriteString("<html><head><title>PoE Port</title></head><body>\n<table>\n")
	b.WriteString("<thead><tr><th>Port</th><th>State</th><th>Power</th><th>Type</th>" +
		"<th>Watts</th><th>Voltage</th><th>Current(mA)</th></tr></thead>\n<tbody>\n")

	for i, p := range s.ports {
		state := "Disable"
		if p.poe.enabled {
			state = "Enable"
		}
		power := "Off"
		if p.poe.powerOn {
			power = "On"
		}
		class, watts, volts, milliamps := "-", "-", "-", "-"
		if p.poe.class >= 0 {
			class = fmt.Sprintf("Class%d", p.poe.class)
			watts = fmt.Sprintf("%.1f", p.poe.watts)
			volts = fmt.Sprintf("%.1f", p.poe.voltage)
			milliamps = fmt.Sprintf("%.1f", p.poe.currentMA)
		}
		b.WriteString(s.row(fmt.Sprintf("Port %d", i+1), state, power, class, watts, volts, milliamps))
	}

	b.WriteString("</tbody>\n</table>\n</body></html>\n")
	return b.String()
}

func (s *Switch) renderPoESystem() string {
	total := 0.0
	for _, p := range s.ports {
		if p.poe.powerOn {
			total += p.poe.watts
		}
	}
	return fmt.Sprintf(`<html><head><title>PoE System</title></head><body>
<form method="post" action="pse_system.cgi">
<input type="hidden" name="pse_con_pwr" value="%.1f">
<table><tr><td>System Power Consumption</td><td>%.1f W</td></tr></table>
</form></body></html>
`, total, total)
}

// row renders a table row, applying the profile's cell decoration.
func (s *Switch) row(cells ...string) string {
	var b strings.Builder
	b.WriteString("<tr>")
	for _, c := range cells {
		if s.profile == ProfileKeepLink {
			// KeepLink prefixes every cell with "0-".
			c = "0-" + c
		}
		fmt.Fprintf(&b, "<td>%s</td>", c)
	}
	b.WriteString("</tr>\n")
	return b.String()
}

// group inserts thousands separators, as some firmwares do.
func group(v uint64) string {
	s := fmt.Sprintf("%d", v)
	var out []byte
	for i, digit := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, digit)
	}
	return string(out)
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec // mirrors the device
	return hex.EncodeToString(sum[:])
}
