package collector

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"cheap-switch-exporter/internal/switchclient"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func ptr[T any](v T) *T { return &v }

// fakeClient is a scripted SwitchClient. It counts calls so caching can be
// asserted, and is mutex protected because Collect may run concurrently.
type fakeClient struct {
	mu sync.Mutex

	ports     []switchclient.Port
	poePorts  []switchclient.PoEPort
	poeSystem switchclient.PoESystem

	portsErr     error
	poePortsErr  error
	poeSystemErr error

	portCalls      int
	poePortCalls   int
	poeSystemCalls int
}

func (f *fakeClient) PortStatistics(context.Context) ([]switchclient.Port, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.portCalls++
	return f.ports, f.portsErr
}

func (f *fakeClient) PoEPorts(context.Context) ([]switchclient.PoEPort, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.poePortCalls++
	return f.poePorts, f.poePortsErr
}

func (f *fakeClient) PoESystem(context.Context) (switchclient.PoESystem, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.poeSystemCalls++
	return f.poeSystem, f.poeSystemErr
}

func (f *fakeClient) calls() (ports, poePorts, poeSystem int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.portCalls, f.poePortCalls, f.poeSystemCalls
}

func samplePorts() []switchclient.Port {
	return []switchclient.Port{
		{
			Name: "1", Enabled: ptr(true), LinkUp: ptr(true),
			TxGoodPkt: ptr(uint64(100)), TxBadPkt: ptr(uint64(1)),
			RxGoodPkt: ptr(uint64(200)), RxBadPkt: ptr(uint64(2)),
		},
		{
			Name: "2", Enabled: ptr(false), LinkUp: ptr(false),
			TxGoodPkt: ptr(uint64(0)), TxBadPkt: ptr(uint64(0)),
			RxGoodPkt: ptr(uint64(0)), RxBadPkt: ptr(uint64(0)),
		},
	}
}

func samplePoEPorts() []switchclient.PoEPort {
	return []switchclient.PoEPort{
		{
			Name: "1", Enabled: ptr(true), PowerOn: ptr(true), Class: ptr(uint8(3)),
			Watts: ptr(3.2), Voltage: ptr(53.1), Current: ptr(60.0),
		},
	}
}

func newTestCollector(t *testing.T, client SwitchClient, poe bool, minInterval time.Duration) *Collector {
	t.Helper()
	return New(context.Background(), Options{
		Client:      client,
		Logger:      discardLogger(),
		PoE:         poe,
		Timeout:     time.Second,
		MinInterval: minInterval,
		Version:     "v1.2.3",
	})
}

// A cancelled lifetime context must abort polls instead of letting shutdown wait
// for the device timeout. The client is expected to observe the cancellation.
func TestCancelledContextAbortsPolls(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client := &ctxObservingClient{}
	c := New(ctx, Options{
		Client:  client,
		Logger:  discardLogger(),
		Timeout: time.Minute,
		Version: "test",
	})

	if err := testutil.CollectAndCompare(c, strings.NewReader(`
# HELP exporter_up Whether the last poll of the switch succeeded (1=yes, 0=no).
# TYPE exporter_up gauge
exporter_up 0
`), "exporter_up"); err != nil {
		t.Error(err)
	}
	if !errors.Is(client.observed, context.Canceled) {
		t.Errorf("the client saw %v, want context.Canceled to reach it", client.observed)
	}
}

// ctxObservingClient reports whatever the collector's context carries.
type ctxObservingClient struct {
	observed error
}

func (c *ctxObservingClient) PortStatistics(ctx context.Context) ([]switchclient.Port, error) {
	c.observed = ctx.Err()
	return nil, ctx.Err()
}

func (c *ctxObservingClient) PoEPorts(ctx context.Context) ([]switchclient.PoEPort, error) {
	return nil, ctx.Err()
}

func (c *ctxObservingClient) PoESystem(ctx context.Context) (switchclient.PoESystem, error) {
	return switchclient.PoESystem{}, ctx.Err()
}

// A nil context must not panic; it is treated as a process-lifetime context.
func TestNewToleratesNilContext(t *testing.T) {
	c := New(nil, Options{ //nolint:staticcheck // exercising the nil guard on purpose
		Client:  &fakeClient{ports: samplePorts()},
		Logger:  discardLogger(),
		Timeout: time.Second,
	})
	if got := testutil.CollectAndCount(c, "port_state"); got != 2 {
		t.Errorf("collected %d port_state samples, want 2", got)
	}
}

// A pedantic registry verifies that every metric Collect emits was announced by
// Describe. The previous implementation omitted all seven PoE descriptors.
func TestDescribeCoversEverythingCollectEmits(t *testing.T) {
	client := &fakeClient{
		ports:     samplePorts(),
		poePorts:  samplePoEPorts(),
		poeSystem: switchclient.PoESystem{ConsumptionWatts: 28.7},
	}
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(newTestCollector(t, client, true, 0)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("Gather returned no metric families")
	}
}

// The constructor must not touch the default registry, so more than one
// collector can exist in a process.
func TestNewHasNoGlobalSideEffects(t *testing.T) {
	client := &fakeClient{ports: samplePorts()}
	for i := 0; i < 3; i++ {
		reg := prometheus.NewPedanticRegistry()
		if err := reg.Register(newTestCollector(t, client, false, 0)); err != nil {
			t.Fatalf("Register #%d: %v", i, err)
		}
	}
}

func TestCollectPortMetrics(t *testing.T) {
	client := &fakeClient{ports: samplePorts()}
	c := newTestCollector(t, client, false, 0)

	const expected = `
# HELP port_link_status Link status of the port (1=Link Up, 0=Link Down).
# TYPE port_link_status gauge
port_link_status{port="1"} 1
port_link_status{port="2"} 0
# HELP port_rx_bad_pkt Number of bad packets received on the port.
# TYPE port_rx_bad_pkt counter
port_rx_bad_pkt{port="1"} 2
port_rx_bad_pkt{port="2"} 0
# HELP port_rx_good_pkt Number of good packets received on the port.
# TYPE port_rx_good_pkt counter
port_rx_good_pkt{port="1"} 200
port_rx_good_pkt{port="2"} 0
# HELP port_state State of the port (1=Enable, 0=Disable).
# TYPE port_state gauge
port_state{port="1"} 1
port_state{port="2"} 0
# HELP port_tx_bad_pkt Number of bad packets transmitted on the port.
# TYPE port_tx_bad_pkt counter
port_tx_bad_pkt{port="1"} 1
port_tx_bad_pkt{port="2"} 0
# HELP port_tx_good_pkt Number of good packets transmitted on the port.
# TYPE port_tx_good_pkt counter
port_tx_good_pkt{port="1"} 100
port_tx_good_pkt{port="2"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"port_state", "port_link_status", "port_tx_good_pkt", "port_tx_bad_pkt",
		"port_rx_good_pkt", "port_rx_bad_pkt"); err != nil {
		t.Error(err)
	}
}

func TestCollectPoEMetrics(t *testing.T) {
	client := &fakeClient{
		ports:     samplePorts(),
		poePorts:  samplePoEPorts(),
		poeSystem: switchclient.PoESystem{ConsumptionWatts: 28.7},
	}
	c := newTestCollector(t, client, true, 0)

	const expected = `
# HELP poe_port_current_ma PoE port current in mA.
# TYPE poe_port_current_ma gauge
poe_port_current_ma{port="1"} 60
# HELP poe_port_power_on PoE port power on/off (1=On, 0=Off).
# TYPE poe_port_power_on gauge
poe_port_power_on{port="1"} 1
# HELP poe_port_state State of the PoE port (1=Enable, 0=Disable).
# TYPE poe_port_state gauge
poe_port_state{port="1"} 1
# HELP poe_port_type PoE port power class (1-8, 0=no powered device).
# TYPE poe_port_type gauge
poe_port_type{port="1"} 3
# HELP poe_port_voltage PoE port voltage in volts.
# TYPE poe_port_voltage gauge
poe_port_voltage{port="1"} 53.1
# HELP poe_port_watts PoE port power consumption in watts.
# TYPE poe_port_watts gauge
poe_port_watts{port="1"} 3.2
# HELP poe_system_consumption_watts Total PoE consumption in watts.
# TYPE poe_system_consumption_watts gauge
poe_system_consumption_watts 28.7
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"poe_port_state", "poe_port_power_on", "poe_port_type", "poe_port_watts",
		"poe_port_voltage", "poe_port_current_ma", "poe_system_consumption_watts"); err != nil {
		t.Error(err)
	}
}

// PoE pages must not be requested when PoE is off.
func TestCollectSkipsPoEWhenDisabled(t *testing.T) {
	client := &fakeClient{ports: samplePorts(), poePorts: samplePoEPorts()}
	c := newTestCollector(t, client, false, 0)

	if _, err := testutil.CollectAndLint(c); err != nil {
		t.Fatalf("CollectAndLint: %v", err)
	}
	if _, poePorts, poeSystem := client.calls(); poePorts != 0 || poeSystem != 0 {
		t.Errorf("PoE was polled %d/%d times, want 0", poePorts, poeSystem)
	}
	if got := testutil.CollectAndCount(c, "poe_port_watts"); got != 0 {
		t.Errorf("collected %d poe_port_watts samples, want 0", got)
	}
}

// The exporter's own metrics must survive a total failure: a series that
// disappears when the device breaks cannot be alerted on.
func TestCollectReportsFailureWithoutLosingMetaMetrics(t *testing.T) {
	client := &fakeClient{portsErr: errors.New("connection refused")}
	c := newTestCollector(t, client, false, 0)

	const expected = `
# HELP exporter_scrape_errors_total Total number of failed requests to the switch.
# TYPE exporter_scrape_errors_total counter
exporter_scrape_errors_total 1
# HELP exporter_up Whether the last poll of the switch succeeded (1=yes, 0=no).
# TYPE exporter_up gauge
exporter_up 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"exporter_up", "exporter_scrape_errors_total"); err != nil {
		t.Error(err)
	}
	if got := testutil.CollectAndCount(c, "port_state"); got != 0 {
		t.Errorf("collected %d port_state samples during a failure, want 0", got)
	}
	if got := testutil.CollectAndCount(c, "exporter_last_scrape_duration_seconds"); got != 1 {
		t.Errorf("collected %d duration samples, want 1", got)
	}
}

func TestCollectReportsSuccess(t *testing.T) {
	client := &fakeClient{ports: samplePorts()}
	c := newTestCollector(t, client, false, 0)

	const expected = `
# HELP exporter_up Whether the last poll of the switch succeeded (1=yes, 0=no).
# TYPE exporter_up gauge
exporter_up 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected), "exporter_up"); err != nil {
		t.Error(err)
	}
}

// A PoE page failing must not hide the port statistics that were read fine.
func TestCollectSurvivesPartialPoEFailure(t *testing.T) {
	client := &fakeClient{
		ports:        samplePorts(),
		poePorts:     samplePoEPorts(),
		poeSystemErr: errors.New("pse_system.cgi: 500"),
	}
	c := newTestCollector(t, client, true, 0)

	if got := testutil.CollectAndCount(c, "port_state"); got != 2 {
		t.Errorf("collected %d port_state samples, want 2", got)
	}
	if got := testutil.CollectAndCount(c, "poe_port_watts"); got != 1 {
		t.Errorf("collected %d poe_port_watts samples, want 1", got)
	}
	if got := testutil.CollectAndCount(c, "poe_system_consumption_watts"); got != 0 {
		t.Errorf("collected %d system consumption samples, want 0", got)
	}
	if err := testutil.CollectAndCompare(c, strings.NewReader(`
# HELP exporter_up Whether the last poll of the switch succeeded (1=yes, 0=no).
# TYPE exporter_up gauge
exporter_up 0
`), "exporter_up"); err != nil {
		t.Error(err)
	}
}

// A counter the device did not report must be omitted rather than published as
// zero, which downstream would look like a device reset.
func TestCollectOmitsUnreadableValues(t *testing.T) {
	client := &fakeClient{ports: []switchclient.Port{{
		Name:      "1",
		Enabled:   ptr(true),
		LinkUp:    nil, // unrecognised link status
		TxGoodPkt: ptr(uint64(5)),
		TxBadPkt:  nil, // the device printed "-"
	}}}
	c := newTestCollector(t, client, false, 0)

	if got := testutil.CollectAndCount(c, "port_tx_good_pkt"); got != 1 {
		t.Errorf("collected %d port_tx_good_pkt samples, want 1", got)
	}
	for _, name := range []string{"port_tx_bad_pkt", "port_link_status", "port_rx_good_pkt"} {
		if got := testutil.CollectAndCount(c, name); got != 0 {
			t.Errorf("collected %d %s samples, want 0", got, name)
		}
	}
}

func TestBuildInfoIsExposed(t *testing.T) {
	client := &fakeClient{ports: samplePorts()}
	c := newTestCollector(t, client, false, 0)

	if got := testutil.CollectAndCount(c, "exporter_build_info"); got != 1 {
		t.Fatalf("collected %d exporter_build_info samples, want 1", got)
	}
	var buf strings.Builder
	metrics, err := testutil.CollectAndLint(c, "exporter_build_info")
	if err != nil {
		t.Fatalf("CollectAndLint: %v", err)
	}
	for _, problem := range metrics {
		buf.WriteString(problem.Text)
	}
	if buf.Len() != 0 {
		t.Errorf("lint problems: %s", buf.String())
	}
}

// Scrapes arriving inside the minimum interval are answered from the previous
// result, which is what keeps these devices alive under HA Prometheus pairs.
func TestMinIntervalCachesPolls(t *testing.T) {
	client := &fakeClient{ports: samplePorts()}
	c := newTestCollector(t, client, false, 10*time.Second)

	now := time.Now()
	c.now = func() time.Time { return now }

	for i := 0; i < 5; i++ {
		if got := testutil.CollectAndCount(c, "port_state"); got != 2 {
			t.Fatalf("collect #%d returned %d samples", i, got)
		}
	}
	if ports, _, _ := client.calls(); ports != 1 {
		t.Errorf("polled the switch %d times within the interval, want 1", ports)
	}

	now = now.Add(11 * time.Second)
	if got := testutil.CollectAndCount(c, "port_state"); got != 2 {
		t.Fatalf("collect after expiry returned %d samples", got)
	}
	if ports, _, _ := client.calls(); ports != 2 {
		t.Errorf("polled the switch %d times after expiry, want 2", ports)
	}
}

// Failures are cached too, otherwise an unreachable switch is retried on every
// single scrape and the requests pile up behind the collector mutex.
func TestMinIntervalCachesFailures(t *testing.T) {
	client := &fakeClient{portsErr: errors.New("i/o timeout")}
	c := newTestCollector(t, client, false, 10*time.Second)

	now := time.Now()
	c.now = func() time.Time { return now }

	for i := 0; i < 4; i++ {
		testutil.CollectAndCount(c, "exporter_up")
	}
	if ports, _, _ := client.calls(); ports != 1 {
		t.Errorf("polled the failing switch %d times, want 1", ports)
	}
	if err := testutil.CollectAndCompare(c, strings.NewReader(`
# HELP exporter_scrape_errors_total Total number of failed requests to the switch.
# TYPE exporter_scrape_errors_total counter
exporter_scrape_errors_total 1
`), "exporter_scrape_errors_total"); err != nil {
		t.Error(err)
	}
}

func TestZeroMinIntervalPollsEveryScrape(t *testing.T) {
	client := &fakeClient{ports: samplePorts()}
	c := newTestCollector(t, client, false, 0)

	for i := 0; i < 3; i++ {
		testutil.CollectAndCount(c, "port_state")
	}
	if ports, _, _ := client.calls(); ports != 3 {
		t.Errorf("polled the switch %d times, want 3", ports)
	}
}

// Run with -race: concurrent scrapes must neither race nor produce duplicates.
func TestConcurrentCollectIsSafe(t *testing.T) {
	client := &fakeClient{
		ports:     samplePorts(),
		poePorts:  samplePoEPorts(),
		poeSystem: switchclient.PoESystem{ConsumptionWatts: 1},
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newTestCollector(t, client, true, 0))

	var wg sync.WaitGroup
	errCh := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := reg.Gather(); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("Gather: %v", err)
	}
}

// The scrape duration must be a real measurement, not left at zero.
func TestScrapeDurationIsMeasured(t *testing.T) {
	client := &fakeClient{ports: samplePorts()}
	c := newTestCollector(t, client, false, 0)

	start := time.Now()
	c.now = func() time.Time {
		start = start.Add(250 * time.Millisecond)
		return start
	}

	if err := testutil.CollectAndCompare(c, strings.NewReader(`
# HELP exporter_last_scrape_duration_seconds Duration of the last poll of the switch.
# TYPE exporter_last_scrape_duration_seconds gauge
exporter_last_scrape_duration_seconds 0.25
`), "exporter_last_scrape_duration_seconds"); err != nil {
		t.Error(err)
	}
}
