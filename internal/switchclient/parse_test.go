package switchclient

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func loadDoc(t *testing.T, name string) *goquery.Document {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("opening fixture: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	doc, err := goquery.NewDocumentFromReader(f)
	if err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	return doc
}

func docFromString(t *testing.T, html string) *goquery.Document {
	t.Helper()
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		t.Fatalf("parsing html: %v", err)
	}
	return doc
}

// fixtureCase describes the statistics page of one device.
//
// Adding support for a new switch starts here: drop its page in testdata and add
// an entry. See "Adding a new device" in the README.
type fixtureCase struct {
	// device is the model the page came from.
	device string
	// file is the fixture inside testdata.
	file string
	// wantPorts is how many rows the parser must recognise.
	wantPorts int
	// wantFirst is the expected content of the first row. A nil field means the
	// exporter must publish no sample for it.
	wantFirst Port
	// extra holds any assertion specific to this device.
	extra func(t *testing.T, ports []Port)
}

var fixtures = []fixtureCase{
	{
		device:    "Horaco ZX-SWTGW218AS and friends",
		file:      "port_stats.html",
		wantPorts: 4,
		wantFirst: Port{
			Name: "1", Enabled: ptr(true), LinkUp: ptr(true),
			TxGoodPkt: ptr(uint64(1234567)), TxBadPkt: ptr(uint64(0)),
			RxGoodPkt: ptr(uint64(7654321)), RxBadPkt: ptr(uint64(3)),
		},
		extra: func(t *testing.T, ports []Port) {
			// Names must be reduced to the bare identifier, and the decoy
			// navigation table must not be read as data.
			for i, want := range []string{"1", "2", "3", "4"} {
				if ports[i].Name != want {
					t.Errorf("ports[%d].Name = %q, want %q", i, ports[i].Name, want)
				}
			}
			if !boolEq(ports[2].Enabled, false) || !boolEq(ports[2].LinkUp, false) {
				t.Errorf("port 3 = %s, want disabled and link down", formatPort(ports[2]))
			}
			// Port 4 has whitespace, a non-breaking space, a grouped number and
			// a dash. The dash must produce no counter at all.
			if !uintEq(ports[3].TxGoodPkt, 1234) {
				t.Errorf("port 4 tx_good_pkt = %s, want 1234", fmtUint(ports[3].TxGoodPkt))
			}
			if ports[3].TxBadPkt != nil {
				t.Errorf("port 4 TxBadPkt = %d, want no sample for a dash", *ports[3].TxBadPkt)
			}
		},
	},
	{
		device:    "KeepLink KP-9000-9XHPML-X",
		file:      "port_stats_keeplink.html",
		wantPorts: 2,
		wantFirst: Port{
			Name: "1", Enabled: ptr(true), LinkUp: ptr(true),
			TxGoodPkt: ptr(uint64(999)), TxBadPkt: ptr(uint64(0)),
			RxGoodPkt: ptr(uint64(888)), RxBadPkt: ptr(uint64(1)),
		},
		extra: func(t *testing.T, ports []Port) {
			// Every cell is prefixed with "0-" on this firmware.
			if !boolEq(ports[1].Enabled, false) || !boolEq(ports[1].LinkUp, false) {
				t.Errorf("port 2 = %s, want disabled and link down", formatPort(ports[1]))
			}
		},
	},
}

func TestParsePortStatisticsFixtures(t *testing.T) {
	for _, tc := range fixtures {
		t.Run(tc.file, func(t *testing.T) {
			ports, err := parsePortStatistics(loadDoc(t, tc.file), discardLogger())
			if err != nil {
				t.Fatalf("%s: %v", tc.device, err)
			}
			if len(ports) != tc.wantPorts {
				t.Fatalf("got %d ports, want %d: %+v", len(ports), tc.wantPorts, ports)
			}
			if !reflect.DeepEqual(ports[0], tc.wantFirst) {
				t.Errorf("first port = %s\n           want %s",
					formatPort(ports[0]), formatPort(tc.wantFirst))
			}
			if tc.extra != nil {
				tc.extra(t, ports)
			}
		})
	}
}

// A wrong password makes these devices answer the login page with HTTP 200. The
// parser has to turn that into an error instead of reporting zero ports.
func TestParsePortStatisticsLoginPage(t *testing.T) {
	_, err := parsePortStatistics(loadDoc(t, "port_stats_login.html"), discardLogger())
	if !errors.Is(err, ErrNoData) {
		t.Fatalf("err = %v, want ErrNoData", err)
	}
}

func TestParsePortStatisticsDeduplicatesPorts(t *testing.T) {
	const html = `<table>
<tr><td>1</td><td>Enable</td><td>Link Up</td><td>1</td><td>0</td><td>1</td><td>0</td></tr>
<tr><td>1</td><td>Enable</td><td>Link Up</td><td>2</td><td>0</td><td>2</td><td>0</td></tr>
</table>`
	ports, err := parsePortStatistics(docFromString(t, html), discardLogger())
	if err != nil {
		t.Fatalf("parsePortStatistics: %v", err)
	}
	// Duplicate label sets make the whole registry Gather fail, so the second
	// row has to be dropped.
	if len(ports) != 1 {
		t.Fatalf("got %d ports, want 1 after de-duplication", len(ports))
	}
	if !uintEq(ports[0].TxGoodPkt, 1) {
		t.Errorf("kept the wrong row: %s", formatPort(ports[0]))
	}
}

func TestParsePortStatisticsBoundsRowCount(t *testing.T) {
	var b strings.Builder
	b.WriteString("<table>")
	for i := 0; i < maxRows+50; i++ {
		fmt.Fprintf(&b, "<tr><td>%d</td><td>Enable</td><td>Link Up</td>"+
			"<td>1</td><td>0</td><td>1</td><td>0</td></tr>", i)
	}
	b.WriteString("</table>")

	ports, err := parsePortStatistics(docFromString(t, b.String()), discardLogger())
	if err != nil {
		t.Fatalf("parsePortStatistics: %v", err)
	}
	if len(ports) != maxRows {
		t.Fatalf("got %d ports, want the %d row cap", len(ports), maxRows)
	}
}

func TestParsePoEPorts(t *testing.T) {
	ports, err := parsePoEPorts(loadDoc(t, "pse_port.html"), discardLogger())
	if err != nil {
		t.Fatalf("parsePoEPorts: %v", err)
	}
	if len(ports) != 4 {
		t.Fatalf("got %d ports, want 4", len(ports))
	}

	if got := ports[0]; got.Name != "1" || !boolEq(got.Enabled, true) || !boolEq(got.PowerOn, true) ||
		!classEq(got.Class, 3) || !floatEq(got.Watts, 3.2) || !floatEq(got.Voltage, 53.1) || !floatEq(got.Current, 60) {
		t.Errorf("poe port 1 = %+v", got)
	}
	// Dashes mean "no powered device": zero watts is the right reading.
	if got := ports[1]; !boolEq(got.PowerOn, false) || !classEq(got.Class, 0) ||
		!floatEq(got.Watts, 0) || !floatEq(got.Current, 0) {
		t.Errorf("poe port 2 = %+v", got)
	}
	// 802.3bt classes above 4 and a unit suffix must both be understood.
	if got := ports[3]; !classEq(got.Class, 6) || !floatEq(got.Watts, 25.5) {
		t.Errorf("poe port 4 = %+v", got)
	}
}

func TestParsePoESystem(t *testing.T) {
	system, err := parsePoESystem(loadDoc(t, "pse_system.html"))
	if err != nil {
		t.Fatalf("parsePoESystem: %v", err)
	}
	if system.ConsumptionWatts != 28.7 {
		t.Errorf("ConsumptionWatts = %v, want 28.7", system.ConsumptionWatts)
	}
}

func TestParsePoESystemErrors(t *testing.T) {
	tests := []struct {
		name    string
		html    string
		wantErr error
	}{
		{"missing input", `<html><body><table></table></body></html>`, ErrNoData},
		{"empty value", `<html><body><input name="pse_con_pwr" value=""></body></html>`, ErrNoData},
		{"not a number", `<html><body><input name="pse_con_pwr" value="abc"></body></html>`, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePoESystem(docFromString(t, tc.html))
			if err == nil {
				t.Fatal("want an error")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestNormalizePortName(t *testing.T) {
	tests := map[string]string{
		"Port 1":  "1",
		"port 12": "12",
		"PORT3":   "3",
		" 7 ":     "7",
		"1":       "1",
		"Port":    "",
		"Trunk1":  "Trunk1",
		"Port  9": "9",
	}
	for in, want := range tests {
		if got := normalizePortName(in); got != want {
			t.Errorf("normalizePortName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCleanNumber(t *testing.T) {
	tests := map[string]string{
		"1234":      "1234",
		"1,234,567": "1234567",
		"12.5 W":    "12.5",
		"480mA":     "480",
		"-":         "-",
		"":          "",
		"TxGoodPkt": "",
		"-5":        "-5",
	}
	for in, want := range tests {
		if got := cleanNumber(in); got != want {
			t.Errorf("cleanNumber(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseUintRejectsUnreadableCells(t *testing.T) {
	for _, in := range []string{"-", "", "n/a", "TxGoodPkt", "1.5"} {
		if got := parseUint(in); got != nil {
			t.Errorf("parseUint(%q) = %d, want nil", in, *got)
		}
	}
	if got := parseUint("42"); !uintEq(got, 42) {
		t.Errorf("parseUint(%q) did not return 42", "42")
	}
}

func TestParseClass(t *testing.T) {
	tests := []struct {
		in   string
		want *uint8
	}{
		{"Class0", ptr(uint8(0))},
		{"Class1", ptr(uint8(1))},
		{"Class4", ptr(uint8(4))},
		{"class 8", ptr(uint8(8))},
		{"-", ptr(uint8(0))},
		{"", ptr(uint8(0))},
		{"Type", nil},
		{"Class9", nil},
	}
	for _, tc := range tests {
		got := parseClass(tc.in)
		switch {
		case tc.want == nil && got != nil:
			t.Errorf("parseClass(%q) = %d, want nil", tc.in, *got)
		case tc.want != nil && !classEq(got, *tc.want):
			t.Errorf("parseClass(%q) = %v, want %d", tc.in, got, *tc.want)
		}
	}
}

func TestParseEnabledAndLinkUp(t *testing.T) {
	for _, in := range []string{"Enable", "enabled", "ENABLE"} {
		if !boolEq(parseEnabled(in), true) {
			t.Errorf("parseEnabled(%q) is not true", in)
		}
	}
	for _, in := range []string{"Disable", "disabled"} {
		if !boolEq(parseEnabled(in), false) {
			t.Errorf("parseEnabled(%q) is not false", in)
		}
	}
	// An unknown spelling must stay unknown so no sample is published.
	if got := parseEnabled("State"); got != nil {
		t.Errorf("parseEnabled(%q) = %t, want nil", "State", *got)
	}
	if !boolEq(parseLinkUp("Link Up"), true) || !boolEq(parseLinkUp("down"), false) {
		t.Error("parseLinkUp did not recognise the usual spellings")
	}
	if got := parseLinkUp("Link Status"); got != nil {
		t.Errorf("parseLinkUp(header) = %t, want nil", *got)
	}
}

func boolEq(got *bool, want bool) bool        { return got != nil && *got == want }
func uintEq(got *uint64, want uint64) bool    { return got != nil && *got == want }
func classEq(got *uint8, want uint8) bool     { return got != nil && *got == want }
func floatEq(got *float64, want float64) bool { return got != nil && *got == want }

func formatPort(p Port) string {
	return fmt.Sprintf("{Name:%s Enabled:%v LinkUp:%v Tx:%v/%v Rx:%v/%v}",
		p.Name, fmtBool(p.Enabled), fmtBool(p.LinkUp),
		fmtUint(p.TxGoodPkt), fmtUint(p.TxBadPkt), fmtUint(p.RxGoodPkt), fmtUint(p.RxBadPkt))
}

func fmtBool(b *bool) string {
	if b == nil {
		return "nil"
	}
	return fmt.Sprint(*b)
}

func fmtUint(v *uint64) string {
	if v == nil {
		return "nil"
	}
	return fmt.Sprint(*v)
}
