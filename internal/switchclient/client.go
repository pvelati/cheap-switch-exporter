// Package switchclient retrieves port and PoE statistics from the HTTP
// management interface of low-cost, SNMP-less network switches.
//
// The devices expose no API: the exporter reproduces what the web UI does and
// scrapes the resulting HTML. Every quirk reproduced here is required by at
// least one supported firmware and is documented at the point where it applies.
package switchclient

import (
	"context"
	"crypto/md5" //nolint:gosec // dictated by the device: the web UI authenticates with an MD5 token
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// Paths of the CGI endpoints of the web interface.
const (
	pathPortStats = "/port.cgi"
	pathPoESystem = "/pse_system.cgi"
	pathPoEPorts  = "/pse_port.cgi"
	pathReferer   = "/menu.cgi"
	pathLogin     = "/login.cgi"
)

// cookieName is the session cookie these web interfaces use.
const cookieName = "admin"

// userAgent identifies the exporter in the device's access log.
const userAgent = "cheap-switch-exporter"

// maxResponseBytes caps how much of a response is read. The pages are a few
// kilobytes; the limit keeps a malfunctioning or hostile endpoint from driving
// the exporter out of memory.
const maxResponseBytes = 4 << 20

// Options configures a Client.
type Options struct {
	// Address is the switch host, optionally with a port. It must not contain
	// a scheme or a path; see config.Validate.
	Address  string
	Username string
	Password string
	// Timeout bounds a single HTTP request, including connection setup.
	Timeout time.Duration
	Logger  *slog.Logger
}

// Client talks to a single switch. It is safe for concurrent use.
type Client struct {
	baseURL string
	http    *http.Client
	logger  *slog.Logger

	// jar holds session cookies the device hands out itself. Some firmwares
	// (Binardat, see issue #8) ignore the synthetic cookie below and only serve
	// data against a session they created.
	jar http.CookieJar

	// body is the pre-encoded credential form. These devices expect it even on
	// GET requests.
	body string
	// token is the session value the web UI stores in the "admin" cookie. It is
	// password-equivalent and must never be logged.
	token string
}

// New builds a Client. Options are not validated here; use config.Validate.
func New(opts Options) *Client {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// md5Hex returns lowercase hex, which is what these firmwares expect. Shells
	// that produce uppercase digests need to fold the case; Go does not.
	token := md5Hex(opts.Username + opts.Password)
	body := url.Values{
		"username": {opts.Username},
		"password": {opts.Password},
		"language": {"EN"},
		"Response": {token},
	}.Encode()

	// The error is always nil for a nil public suffix list.
	jar, _ := cookiejar.New(nil)

	return &Client{
		baseURL: "http://" + opts.Address,
		logger:  logger,
		jar:     jar,
		body:    body,
		token:   token,
		http: &http.Client{
			Timeout: opts.Timeout,
			Jar:     jar,
			// Never follow redirects: a redirect off the device would leak the
			// credential cookie to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				// Deliberately no Proxy: these are link-local management
				// interfaces, and honouring HTTP_PROXY would send the
				// credentials to an unrelated host.
				Proxy: nil,
				DialContext: (&net.Dialer{
					Timeout:   opts.Timeout,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				MaxIdleConns:          2,
				MaxIdleConnsPerHost:   2,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   opts.Timeout,
				ExpectContinueTimeout: time.Second,
				// The pages are tiny and some firmwares mishandle gzip.
				DisableCompression: true,
			},
		},
	}
}

// PortStatistics returns one entry per port of the statistics page.
func (c *Client) PortStatistics(ctx context.Context) ([]Port, error) {
	return fetchAndParse(ctx, c, pathPortStats, func(doc *goquery.Document) ([]Port, error) {
		return parsePortStatistics(doc, c.logger)
	})
}

// PoESystem returns the switch-wide PoE figures.
func (c *Client) PoESystem(ctx context.Context) (PoESystem, error) {
	return fetchAndParse(ctx, c, pathPoESystem, parsePoESystem)
}

// PoEPorts returns one entry per port of the PoE page.
func (c *Client) PoEPorts(ctx context.Context) ([]PoEPort, error) {
	return fetchAndParse(ctx, c, pathPoEPorts, func(doc *goquery.Document) ([]PoEPort, error) {
		return parsePoEPorts(doc, c.logger)
	})
}

// fetchAndParse retrieves path and parses it, authenticating once and retrying
// if the device answered with something that holds no data.
//
// These web interfaces keep session state. Several firmwares (HC-SWTGW218AS in
// issue #19, Binardat in issue #8) serve the login page with HTTP 200 once the
// session is gone, which is why the exporter used to return values only while a
// browser happened to be logged in. Authenticating lazily, on the first empty
// answer, keeps the happy path at one request per page.
func fetchAndParse[T any](
	ctx context.Context,
	c *Client,
	path string,
	parse func(*goquery.Document) (T, error),
) (T, error) {
	var zero T

	out, err := getAndParse(ctx, c, path, parse)
	if err == nil || !errors.Is(err, ErrNoData) {
		return out, err
	}

	c.logger.Debug("no data in response, establishing a session", "path", path)
	if loginErr := c.login(ctx); loginErr != nil {
		return zero, fmt.Errorf("%w (authentication also failed: %w)", err, loginErr)
	}
	return getAndParse(ctx, c, path, parse)
}

func getAndParse[T any](
	ctx context.Context,
	c *Client,
	path string,
	parse func(*goquery.Document) (T, error),
) (T, error) {
	doc, err := c.fetch(ctx, path)
	if err != nil {
		var zero T
		return zero, err
	}
	return parse(doc)
}

// login establishes a session by posting the credential form to /login.cgi.
//
// Any response below 400 counts as success: the firmwares disagree on what they
// return (200 with a redirecting script, or a 302), and the retried data request
// is the real test of whether the session works. Verifying a specific marker
// here would only add another firmware-specific string to maintain.
func (c *Client) login(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+pathLogin, strings.NewReader(c.body))
	if err != nil {
		return fmt.Errorf("building login request: %w", err)
	}
	c.addAuthCookie(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", c.baseURL+"/")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("requesting %s: %w", pathLogin, err)
	}
	defer drainAndClose(resp)

	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("requesting %s: unexpected status %s", pathLogin, resp.Status)
	}
	return nil
}

// addAuthCookie sends the synthetic credential cookie, unless the device has
// already handed out a session cookie of its own. The jar replays that one, and
// sending both would leave the firmware to pick.
func (c *Client) addAuthCookie(req *http.Request) {
	for _, existing := range c.jar.Cookies(req.URL) {
		if existing.Name == cookieName {
			return
		}
	}
	//nolint:gosec // G124 applies to cookies a server sets, not to one sent in a request
	req.AddCookie(&http.Cookie{Name: cookieName, Value: c.token})
}

// drainAndClose reads the remainder of the body within the limit so the
// connection can be reused, then closes it.
func drainAndClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	_ = resp.Body.Close()
}

// fetch performs an authenticated request and parses the response as HTML.
func (c *Client) fetch(ctx context.Context, path string) (*goquery.Document, error) {
	// The web UI authenticates a GET by sending the credential form as the
	// request body. It is unusual but required by every supported firmware.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+path+"?page=stats", strings.NewReader(c.body))
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", path, err)
	}
	c.addAuthCookie(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// KeepLink KP-9000-9XHPML-X returns an empty page without a Referer.
	req.Header.Set("Referer", c.baseURL+pathReferer)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting %s: %w", path, err)
	}
	defer drainAndClose(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("requesting %s: unexpected status %s", path, resp.Status)
	}

	doc, err := goquery.NewDocumentFromReader(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("parsing %s response: %w", path, err)
	}
	return doc, nil
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec // the device's authentication scheme
	return hex.EncodeToString(sum[:])
}
