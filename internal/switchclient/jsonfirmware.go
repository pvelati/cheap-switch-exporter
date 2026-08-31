package switchclient

// Support for firmwares that expose statistics as JSON instead of HTML, such as
// the MaxLinear based Goodtop ZX310S-8T2XS reported in issue #6. The protocol was
// contributed by @jauling:
//
//	GET /authorize?loginusr=<md5(user)>&loginpwd=<md5(pass)>
//	GET /port_statistics.json
//
// Note that the credentials are hashed separately here, unlike the HTML family
// which sends a single md5(username+password) token.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	pathAuthorize     = "/authorize"
	pathPortStatsJSON = "/port_statistics.json"
)

// ErrUnsupported means the firmware does not expose the requested statistics.
var ErrUnsupported = errors.New("not supported by this firmware")

// JSONClient talks to a switch that serves JSON. It is safe for concurrent use.
type JSONClient struct {
	baseURL string
	http    *http.Client
	logger  *slog.Logger
	// authQuery is the pre-encoded credential query for /authorize.
	authQuery string
}

// NewJSON builds a client for the JSON firmware family.
func NewJSON(opts Options) *JSONClient {
	base := New(opts) // reuse the hardened transport and the cookie jar
	return &JSONClient{
		baseURL: base.baseURL,
		http:    base.http,
		logger:  base.logger,
		authQuery: url.Values{
			"loginusr": {md5Hex(opts.Username)},
			"loginpwd": {md5Hex(opts.Password)},
		}.Encode(),
	}
}

// PortStatistics returns one entry per port, authenticating first if the device
// refuses the request.
func (c *JSONClient) PortStatistics(ctx context.Context) ([]Port, error) {
	ports, err := c.readPorts(ctx)
	if err == nil || !errors.Is(err, ErrNoData) {
		return ports, err
	}

	c.logger.Debug("no data in response, authorising", "path", pathPortStatsJSON)
	if authErr := c.authorize(ctx); authErr != nil {
		return nil, fmt.Errorf("%w (authorisation also failed: %w)", err, authErr)
	}
	return c.readPorts(ctx)
}

// PoEPorts is not implemented: no PoE endpoint has been reported for this
// firmware family. Configuration validation rejects poe with firmware: json, so
// this is only a guard.
func (c *JSONClient) PoEPorts(context.Context) ([]PoEPort, error) {
	return nil, fmt.Errorf("PoE port statistics: %w", ErrUnsupported)
}

// PoESystem is not implemented; see PoEPorts.
func (c *JSONClient) PoESystem(context.Context) (PoESystem, error) {
	return PoESystem{}, fmt.Errorf("PoE system statistics: %w", ErrUnsupported)
}

func (c *JSONClient) readPorts(ctx context.Context) ([]Port, error) {
	body, err := c.get(ctx, pathPortStatsJSON, "")
	if err != nil {
		return nil, err
	}
	return parseJSONPortStatistics(body, c.logger)
}

// authorize establishes a session. As with the HTML family, any response below
// 400 counts as success and the retried data request is the real test.
func (c *JSONClient) authorize(ctx context.Context) error {
	if _, err := c.get(ctx, pathAuthorize, c.authQuery); err != nil {
		return err
	}
	return nil
}

func (c *JSONClient) get(ctx context.Context, path, query string) ([]byte, error) {
	target := c.baseURL + path
	if query != "" {
		target += "?" + query
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", path, err)
	}
	req.Header.Set("Accept", "application/json, text/plain")
	req.Header.Set("Referer", c.baseURL+"/")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting %s: %w", path, err)
	}
	defer drainAndClose(resp)

	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("requesting %s: unexpected status %s", path, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading %s response: %w", path, err)
	}
	return body, nil
}

// jsonPort is one "Port_N" object. Every value is a string on this firmware.
type jsonPort struct {
	PortID     string `json:"Port_Id"`
	PortStatus string `json:"Port_Status"`
	LinkStatus string `json:"Link_Status"`
	TxGoodPkt  string `json:"TxGoodPkt"`
	TxBadPkt   string `json:"TxBadPkt"`
	RxGoodPkt  string `json:"RxGoodPkt"`
	RxBadPkt   string `json:"RxBadPkt"`
}

// parseJSONPortStatistics reads /port_statistics.json.
//
// The ports are top-level "Port_N" keys rather than an array, so they have to be
// collected and sorted numerically: Go map iteration order is random, and label
// values would otherwise be attached to rows in an arbitrary order.
func parseJSONPortStatistics(data []byte, logger *slog.Logger) ([]Port, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		// An HTML login page lands here, which is the usual "not authorised yet"
		// case, so report it as missing data rather than as a parse failure.
		return nil, fmt.Errorf("%w (response is not the expected JSON: %w)", ErrNoData, err)
	}

	type row struct {
		index int
		port  jsonPort
	}
	var rows []row
	for key, value := range raw {
		rest, ok := cutPrefixFold(key, "port_")
		if !ok {
			continue // PortNum and anything else the firmware adds
		}
		index, err := strconv.Atoi(rest)
		if err != nil {
			continue
		}
		var p jsonPort
		if err := json.Unmarshal(value, &p); err != nil {
			logger.Debug("ignoring unreadable port entry", "key", key, "err", err)
			continue
		}
		rows = append(rows, row{index: index, port: p})
	}
	if len(rows) == 0 {
		return nil, ErrNoData
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].index < rows[j].index })

	ports := make([]Port, 0, len(rows))
	seen := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		name := normalizePortName(r.port.PortID)
		if name == "" {
			name = strconv.Itoa(r.index)
		}
		if _, dup := seen[name]; dup {
			logger.Warn("ignoring duplicate port entry", "port", name)
			continue
		}
		seen[name] = struct{}{}

		linkUp, speed := parseJSONLinkStatus(r.port.LinkStatus)
		port := Port{
			Name:          name,
			Enabled:       parseEnabled(r.port.PortStatus),
			LinkUp:        linkUp,
			LinkSpeedMbps: speed,
			TxGoodPkt:     parseUint(r.port.TxGoodPkt),
			TxBadPkt:      parseUint(r.port.TxBadPkt),
			RxGoodPkt:     parseUint(r.port.RxGoodPkt),
			RxBadPkt:      parseUint(r.port.RxBadPkt),
		}
		if port.Enabled == nil {
			logger.Debug("unrecognised port state", "port", name, "value", r.port.PortStatus)
		}
		if port.LinkUp == nil {
			logger.Debug("unrecognised link status", "port", name, "value", r.port.LinkStatus)
		}
		ports = append(ports, port)
		if len(ports) >= maxRows {
			break
		}
	}
	if len(ports) == 0 {
		return nil, ErrNoData
	}
	return ports, nil
}

// linkSpeed matches the combined speed and duplex field, "1000MbpsFull" or
// "10GbpsFull".
var linkSpeed = regexp.MustCompile(`^(\d+)\s*(g|m)bps`)

// parseJSONLinkStatus splits the Link_Status field into a link state and, when
// the firmware reports it, a negotiated speed in Mbps. A 2.5G port that has
// negotiated 1G is one of the more useful things to be able to alert on.
func parseJSONLinkStatus(s string) (up *bool, speedMbps *uint64) {
	key := foldKey(s)
	switch key {
	case "", "-", "down", "link down", "nolink", "no link", "not connected":
		return ptr(false), nil
	}

	match := linkSpeed.FindStringSubmatch(key)
	if match == nil {
		// Fall back to the spellings the HTML family uses.
		return parseLinkUp(s), nil
	}
	value, err := strconv.ParseUint(match[1], 10, 64)
	if err != nil {
		return ptr(true), nil
	}
	if match[2] == "g" {
		value *= 1000
	}
	return ptr(true), &value
}

// cutPrefixFold removes a case-insensitive prefix.
func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return "", false
	}
	return s[len(prefix):], true
}
