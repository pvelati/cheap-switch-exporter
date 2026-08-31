package switchclient

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// ErrNoData means the response contained no rows the exporter recognises. It is
// almost always wrong credentials (the device answers with the login page and
// HTTP 200) or an unsupported firmware layout.
var ErrNoData = errors.New("no data rows found in the switch response; check the credentials and whether the device is supported")

const (
	// Both tables have seven columns. Requiring an exact match keeps unrelated
	// tables on the same page from being mistaken for data.
	portStatsColumns = 7
	poePortColumns   = 7
	// maxRows bounds the number of series a single response can create, so a
	// broken page cannot blow up the time series cardinality.
	maxRows = 256
)

// Port is one row of the port statistics table.
//
// The optional fields are nil when the device reported a value the exporter
// cannot interpret. The collector then omits that sample rather than publishing
// a zero, which on a counter would look like a device reset.
type Port struct {
	Name    string
	Enabled *bool
	LinkUp  *bool
	// LinkSpeedMbps is the negotiated speed, when the firmware reports one.
	// Only the JSON family does; it is nil for the HTML family.
	LinkSpeedMbps *uint64
	TxGoodPkt     *uint64
	TxBadPkt      *uint64
	RxGoodPkt     *uint64
	RxBadPkt      *uint64
}

func (p Port) hasValue() bool {
	return p.Enabled != nil || p.LinkUp != nil || p.LinkSpeedMbps != nil ||
		p.TxGoodPkt != nil || p.TxBadPkt != nil || p.RxGoodPkt != nil || p.RxBadPkt != nil
}

// PoEPort is one row of the PoE port table.
type PoEPort struct {
	Name    string
	Enabled *bool
	PowerOn *bool
	// Class is the IEEE power class. Zero means no powered device is attached.
	Class   *uint8
	Watts   *float64
	Voltage *float64
	Current *float64
}

func (p PoEPort) hasValue() bool {
	return p.Enabled != nil || p.PowerOn != nil || p.Class != nil ||
		p.Watts != nil || p.Voltage != nil || p.Current != nil
}

// PoESystem holds the switch-wide PoE figures.
type PoESystem struct {
	ConsumptionWatts float64
}

// parsePortStatistics extracts the port statistics table.
//
// Rows are recognised by shape and content rather than by position, because the
// statistics table is not always the first table on the page and not every
// firmware marks its header row with <th>.
func parsePortStatistics(doc *goquery.Document, logger *slog.Logger) ([]Port, error) {
	var ports []Port
	seen := make(map[string]struct{})

	doc.Find("tr").EachWithBreak(func(_ int, row *goquery.Selection) bool {
		cells, ok := dataCells(row, portStatsColumns)
		if !ok {
			return true
		}
		port := Port{
			Name:      normalizePortName(cells[0]),
			Enabled:   parseEnabled(cells[1]),
			LinkUp:    parseLinkUp(cells[2]),
			TxGoodPkt: parseUint(cells[3]),
			TxBadPkt:  parseUint(cells[4]),
			RxGoodPkt: parseUint(cells[5]),
			RxBadPkt:  parseUint(cells[6]),
		}
		// Header rows and unrelated seven-column tables yield no usable value.
		if port.Name == "" || !port.hasValue() {
			return true
		}
		if _, dup := seen[port.Name]; dup {
			logger.Warn("ignoring duplicate port row", "port", port.Name)
			return true
		}
		seen[port.Name] = struct{}{}

		if port.Enabled == nil {
			logger.Debug("unrecognised port state", "port", port.Name, "value", cells[1])
		}
		if port.LinkUp == nil {
			logger.Debug("unrecognised link status", "port", port.Name, "value", cells[2])
		}

		ports = append(ports, port)
		return len(ports) < maxRows
	})

	if len(ports) == 0 {
		return nil, ErrNoData
	}
	return ports, nil
}

// parsePoEPorts extracts the PoE port table.
func parsePoEPorts(doc *goquery.Document, logger *slog.Logger) ([]PoEPort, error) {
	var ports []PoEPort
	seen := make(map[string]struct{})

	doc.Find("tr").EachWithBreak(func(_ int, row *goquery.Selection) bool {
		cells, ok := dataCells(row, poePortColumns)
		if !ok {
			return true
		}
		port := PoEPort{
			Name:    normalizePortName(cells[0]),
			Enabled: parseEnabled(cells[1]),
			PowerOn: parsePowerOn(cells[2]),
			Class:   parseClass(cells[3]),
			Watts:   parseFloat(cells[4]),
			Voltage: parseFloat(cells[5]),
			Current: parseFloat(cells[6]),
		}
		if port.Name == "" || !port.hasValue() {
			return true
		}
		if _, dup := seen[port.Name]; dup {
			logger.Warn("ignoring duplicate PoE port row", "port", port.Name)
			return true
		}
		seen[port.Name] = struct{}{}
		ports = append(ports, port)
		return len(ports) < maxRows
	})

	if len(ports) == 0 {
		return nil, ErrNoData
	}
	return ports, nil
}

// parsePoESystem extracts the total PoE consumption from its hidden input.
func parsePoESystem(doc *goquery.Document) (PoESystem, error) {
	raw, ok := doc.Find(`input[name="pse_con_pwr"]`).First().Attr("value")
	if !ok || strings.TrimSpace(raw) == "" {
		return PoESystem{}, fmt.Errorf("%w (pse_con_pwr input missing or empty)", ErrNoData)
	}
	watts := parseFloat(normalizeSpace(raw))
	if watts == nil {
		return PoESystem{}, fmt.Errorf("invalid PoE consumption value %q", raw)
	}
	return PoESystem{ConsumptionWatts: *watts}, nil
}

// dataCells returns the normalised text of the direct <td> children of row, but
// only when the row looks like a data row with exactly want columns.
func dataCells(row *goquery.Selection, want int) ([]string, bool) {
	if row.ChildrenFiltered("th").Length() > 0 {
		return nil, false
	}
	tds := row.ChildrenFiltered("td")
	if tds.Length() != want {
		return nil, false
	}
	cells := make([]string, 0, want)
	tds.Each(func(_ int, td *goquery.Selection) {
		cells = append(cells, cellText(td))
	})
	return cells, true
}

// cellText normalises the text of a table cell. KeepLink KP-9000-9XHPML-X
// prefixes every cell with "0-".
func cellText(s *goquery.Selection) string {
	return strings.TrimPrefix(normalizeSpace(s.Text()), "0-")
}

// normalizeSpace trims the cell and collapses internal whitespace runs, which
// also removes the non-breaking spaces some firmwares emit.
func normalizeSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// normalizePortName reduces the spellings used by the various firmwares
// ("Port 1", "port1", " 1 ") to the bare identifier used as label value.
func normalizePortName(s string) string {
	s = normalizeSpace(s)
	if len(s) >= 4 && strings.EqualFold(s[:4], "port") {
		s = strings.TrimSpace(s[4:])
	}
	return s
}

func foldKey(s string) string {
	return strings.ToLower(normalizeSpace(s))
}

func parseEnabled(s string) *bool {
	switch foldKey(s) {
	case "enable", "enabled":
		return ptr(true)
	case "disable", "disabled":
		return ptr(false)
	}
	return nil
}

func parseLinkUp(s string) *bool {
	switch foldKey(s) {
	case "link up", "linkup", "up":
		return ptr(true)
	case "link down", "linkdown", "down":
		return ptr(false)
	}
	return nil
}

func parsePowerOn(s string) *bool {
	switch foldKey(s) {
	case "on", "power on", "true", "1":
		return ptr(true)
	// A dash means no powered device is attached, so no power is delivered.
	case "off", "power off", "false", "0", "-":
		return ptr(false)
	}
	return nil
}

// parseClass maps the PoE "Type" column ("Class3", "class 4", "-") to the IEEE
// power class, covering 802.3bt classes 5 to 8 as well.
func parseClass(s string) *uint8 {
	key := foldKey(s)
	if key == "-" || key == "" || key == "n/a" {
		return ptr(uint8(0))
	}
	digits := cleanNumber(strings.TrimPrefix(key, "class"))
	if digits == "" {
		return nil
	}
	v, err := strconv.ParseUint(digits, 10, 8)
	if err != nil || v > 8 {
		return nil
	}
	return ptr(uint8(v))
}

// parseUint reads a counter cell. Unreadable cells yield nil so the caller can
// skip the sample instead of reporting a fake zero.
func parseUint(s string) *uint64 {
	cleaned := cleanNumber(s)
	if cleaned == "" {
		return nil
	}
	v, err := strconv.ParseUint(cleaned, 10, 64)
	if err != nil {
		return nil
	}
	return &v
}

// parseFloat reads a gauge cell. A dash or an empty cell is how these devices
// report "nothing attached", which for a PoE reading is zero.
func parseFloat(s string) *float64 {
	if s == "-" || s == "" {
		return ptr(0.0)
	}
	cleaned := cleanNumber(s)
	if cleaned == "" {
		return nil
	}
	v, err := strconv.ParseFloat(cleaned, 64)
	if err != nil {
		return nil
	}
	return &v
}

// cleanNumber keeps the leading numeric part of a cell, dropping the grouping
// separators and units some firmwares add ("1,234,567" -> "1234567",
// "12.5 W" -> "12.5"). The web UI is always queried with language=EN, so a
// comma is a thousands separator and never a decimal mark.
func cleanNumber(s string) string {
	s = strings.NewReplacer(",", "", " ", "").Replace(s)
	end := 0
	for i, r := range s {
		isDigit := r >= '0' && r <= '9'
		isSign := i == 0 && (r == '+' || r == '-')
		if !isDigit && r != '.' && !isSign {
			break
		}
		end = i + 1
	}
	return s[:end]
}

func ptr[T any](v T) *T {
	return &v
}
