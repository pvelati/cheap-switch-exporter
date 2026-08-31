// Package collector exposes the statistics of a cheap network switch as
// Prometheus metrics.
//
// The metric names are the ones documented since the first release of the
// exporter and are deliberately left unprefixed for backwards compatibility.
package collector

import (
	"context"
	"errors"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"cheap-switch-exporter/internal/switchclient"
)

// SwitchClient is the part of the switch API the collector uses. It is an
// interface so the collector can be exercised without a device.
type SwitchClient interface {
	PortStatistics(ctx context.Context) ([]switchclient.Port, error)
	PoESystem(ctx context.Context) (switchclient.PoESystem, error)
	PoEPorts(ctx context.Context) ([]switchclient.PoEPort, error)
}

// Options configures a Collector.
type Options struct {
	Client SwitchClient
	Logger *slog.Logger
	// PoE enables the PoE pages.
	PoE bool
	// Timeout bounds a single request to the switch. The collector allows this
	// budget per request it has to make during one scrape.
	Timeout time.Duration
	// MinInterval is the shortest delay between two polls of the device.
	// Scrapes arriving sooner are answered from the previous result. Zero
	// polls on every scrape.
	MinInterval time.Duration
	// Version is reported by exporter_build_info.
	Version string
}

// Collector implements prometheus.Collector.
//
// Collect performs network I/O, so it holds a mutex for the whole call: these
// switches serve a single session at a time and fall over under concurrent
// requests. Combined with MinInterval this bounds the load the exporter can put
// on a device no matter how many Prometheus servers scrape it.
type Collector struct {
	client      SwitchClient
	logger      *slog.Logger
	poe         bool
	timeout     time.Duration
	minInterval time.Duration
	version     string
	now         func() time.Time
	// baseCtx bounds the lifetime of every poll. It is held in the struct
	// because prometheus.Collector.Collect takes no context, and cancelling it
	// is what lets the process stop without waiting for a stuck device.
	baseCtx context.Context

	mu           sync.Mutex
	cache        *result
	cacheExpires time.Time
	scrapeErrors float64

	portState      *prometheus.Desc
	portLinkStatus *prometheus.Desc
	portTxGoodPkt  *prometheus.Desc
	portTxBadPkt   *prometheus.Desc
	portRxGoodPkt  *prometheus.Desc
	portRxBadPkt   *prometheus.Desc

	poeSystemConsumption *prometheus.Desc
	poeState             *prometheus.Desc
	poePower             *prometheus.Desc
	poeType              *prometheus.Desc
	poeWatts             *prometheus.Desc
	poeVoltage           *prometheus.Desc
	poeCurrent           *prometheus.Desc

	up             *prometheus.Desc
	scrapeDuration *prometheus.Desc
	scrapeErrorsD  *prometheus.Desc
	buildInfo      *prometheus.Desc
}

// result is one poll of the switch, kept for at most MinInterval.
type result struct {
	ports     []switchclient.Port
	poePorts  []switchclient.PoEPort
	poeSystem *switchclient.PoESystem
	duration  time.Duration
	err       error
}

// New builds a Collector. It registers nothing by itself: the caller decides
// which registry the collector belongs to.
//
// Polls are bound to ctx, so cancelling it aborts an in-flight request to the
// switch instead of making shutdown wait for the device timeout.
func New(ctx context.Context, opts Options) *Collector {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	version := opts.Version
	if version == "" {
		version = "unknown"
	}
	if ctx == nil {
		ctx = context.Background()
	}

	portLabels := []string{"port"}
	return &Collector{
		client:      opts.Client,
		logger:      logger,
		poe:         opts.PoE,
		timeout:     opts.Timeout,
		minInterval: opts.MinInterval,
		version:     version,
		now:         time.Now,
		baseCtx:     ctx,

		portState: prometheus.NewDesc("port_state",
			"State of the port (1=Enable, 0=Disable).", portLabels, nil),
		portLinkStatus: prometheus.NewDesc("port_link_status",
			"Link status of the port (1=Link Up, 0=Link Down).", portLabels, nil),
		portTxGoodPkt: prometheus.NewDesc("port_tx_good_pkt",
			"Number of good packets transmitted on the port.", portLabels, nil),
		portTxBadPkt: prometheus.NewDesc("port_tx_bad_pkt",
			"Number of bad packets transmitted on the port.", portLabels, nil),
		portRxGoodPkt: prometheus.NewDesc("port_rx_good_pkt",
			"Number of good packets received on the port.", portLabels, nil),
		portRxBadPkt: prometheus.NewDesc("port_rx_bad_pkt",
			"Number of bad packets received on the port.", portLabels, nil),

		poeSystemConsumption: prometheus.NewDesc("poe_system_consumption_watts",
			"Total PoE consumption in watts.", nil, nil),
		poeState: prometheus.NewDesc("poe_port_state",
			"State of the PoE port (1=Enable, 0=Disable).", portLabels, nil),
		poePower: prometheus.NewDesc("poe_port_power_on",
			"PoE port power on/off (1=On, 0=Off).", portLabels, nil),
		poeType: prometheus.NewDesc("poe_port_type",
			"PoE port power class (1-8, 0=no powered device).", portLabels, nil),
		poeWatts: prometheus.NewDesc("poe_port_watts",
			"PoE port power consumption in watts.", portLabels, nil),
		poeVoltage: prometheus.NewDesc("poe_port_voltage",
			"PoE port voltage in volts.", portLabels, nil),
		poeCurrent: prometheus.NewDesc("poe_port_current_ma",
			"PoE port current in mA.", portLabels, nil),

		up: prometheus.NewDesc("exporter_up",
			"Whether the last poll of the switch succeeded (1=yes, 0=no).", nil, nil),
		scrapeDuration: prometheus.NewDesc("exporter_last_scrape_duration_seconds",
			"Duration of the last poll of the switch.", nil, nil),
		scrapeErrorsD: prometheus.NewDesc("exporter_scrape_errors_total",
			"Total number of failed requests to the switch.", nil, nil),
		buildInfo: prometheus.NewDesc("exporter_build_info",
			"Build information of the running exporter.",
			[]string{"version", "goversion"}, nil),
	}
}

// Describe implements prometheus.Collector. Every descriptor Collect can emit
// is announced here, which is what lets the registry detect conflicts at
// registration time.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.portState, c.portLinkStatus, c.portTxGoodPkt, c.portTxBadPkt,
		c.portRxGoodPkt, c.portRxBadPkt,
		c.poeSystemConsumption, c.poeState, c.poePower, c.poeType,
		c.poeWatts, c.poeVoltage, c.poeCurrent,
		c.up, c.scrapeDuration, c.scrapeErrorsD, c.buildInfo,
	} {
		ch <- d
	}
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()

	res := c.currentResult()

	// The exporter's own metrics are emitted unconditionally: a series that
	// disappears exactly when the switch breaks cannot be alerted on.
	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, boolValue(res.err == nil))
	ch <- prometheus.MustNewConstMetric(c.scrapeDuration, prometheus.GaugeValue, res.duration.Seconds())
	ch <- prometheus.MustNewConstMetric(c.scrapeErrorsD, prometheus.CounterValue, c.scrapeErrors)
	ch <- prometheus.MustNewConstMetric(c.buildInfo, prometheus.GaugeValue, 1, c.version, runtime.Version())

	for _, p := range res.ports {
		emitBool(ch, c.portState, p.Enabled, p.Name)
		emitBool(ch, c.portLinkStatus, p.LinkUp, p.Name)
		emit(ch, c.portTxGoodPkt, prometheus.CounterValue, p.TxGoodPkt, p.Name)
		emit(ch, c.portTxBadPkt, prometheus.CounterValue, p.TxBadPkt, p.Name)
		emit(ch, c.portRxGoodPkt, prometheus.CounterValue, p.RxGoodPkt, p.Name)
		emit(ch, c.portRxBadPkt, prometheus.CounterValue, p.RxBadPkt, p.Name)
	}

	if res.poeSystem != nil {
		ch <- prometheus.MustNewConstMetric(c.poeSystemConsumption,
			prometheus.GaugeValue, res.poeSystem.ConsumptionWatts)
	}
	for _, p := range res.poePorts {
		emitBool(ch, c.poeState, p.Enabled, p.Name)
		emitBool(ch, c.poePower, p.PowerOn, p.Name)
		emit(ch, c.poeType, prometheus.GaugeValue, p.Class, p.Name)
		emit(ch, c.poeWatts, prometheus.GaugeValue, p.Watts, p.Name)
		emit(ch, c.poeVoltage, prometheus.GaugeValue, p.Voltage, p.Name)
		emit(ch, c.poeCurrent, prometheus.GaugeValue, p.Current, p.Name)
	}
}

// currentResult returns the cached poll when it is still fresh, otherwise it
// polls the switch. Failures are cached too, so an unreachable device is not
// retried on every single scrape. The caller must hold c.mu.
func (c *Collector) currentResult() *result {
	now := c.now()
	if c.cache != nil && now.Before(c.cacheExpires) {
		return c.cache
	}

	res := c.scrape()
	if c.minInterval > 0 {
		c.cache = res
		c.cacheExpires = now.Add(c.minInterval)
	}
	return res
}

// scrape polls the switch. Partial failures are reported through exporter_up
// while everything that could be read is still exposed. The caller must hold
// c.mu.
func (c *Collector) scrape() *result {
	start := c.now()
	res := &result{}

	requests := 1
	if c.poe {
		requests = 3
	}
	ctx, cancel := context.WithTimeout(c.baseCtx, c.timeout*time.Duration(requests))
	defer cancel()

	var errs []error
	ports, err := c.client.PortStatistics(ctx)
	if err != nil {
		errs = append(errs, err)
		c.recordError("fetching port statistics", err)
	} else {
		res.ports = ports
	}

	if c.poe {
		if system, err := c.client.PoESystem(ctx); err != nil {
			errs = append(errs, err)
			c.recordError("fetching PoE system statistics", err)
		} else {
			res.poeSystem = &system
		}
		if poePorts, err := c.client.PoEPorts(ctx); err != nil {
			errs = append(errs, err)
			c.recordError("fetching PoE port statistics", err)
		} else {
			res.poePorts = poePorts
		}
	}

	res.err = errors.Join(errs...)
	res.duration = c.now().Sub(start)
	return res
}

func (c *Collector) recordError(what string, err error) {
	c.scrapeErrors++
	c.logger.Error(what+" failed", "err", err)
}

// emit sends a sample for an optional numeric value, skipping it when the device
// did not report anything usable.
func emit[T uint64 | uint8 | float64](
	ch chan<- prometheus.Metric,
	desc *prometheus.Desc,
	valueType prometheus.ValueType,
	value *T,
	labels ...string,
) {
	if value == nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(desc, valueType, float64(*value), labels...)
}

func emitBool(ch chan<- prometheus.Metric, desc *prometheus.Desc, value *bool, labels ...string) {
	if value == nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, boolValue(*value), labels...)
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
