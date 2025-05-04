package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

func (sc *switchScrapeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- sc.descs.probeSuccess
	ch <- sc.descs.probeDurationSeconds
	ch <- sc.descs.portState
	ch <- sc.descs.portLinkStatus
	ch <- sc.descs.portTxGoodPkt
	ch <- sc.descs.portTxBadPkt
	ch <- sc.descs.portRxGoodPkt
	ch <- sc.descs.portRxBadPkt
	ch <- sc.descs.portRSTPState
	ch <- sc.descs.portRSTPCost
}

func (sc *switchScrapeCollector) Collect(ch chan<- prometheus.Metric) {
	successValue := 0.0
	if sc.probeSuccess {
		successValue = 1.0
	}
	ch <- prometheus.MustNewConstMetric(sc.descs.probeSuccess, prometheus.GaugeValue, successValue, sc.targetLabelValue)
	ch <- prometheus.MustNewConstMetric(sc.descs.probeDurationSeconds, prometheus.GaugeValue, sc.probeDuration, sc.targetLabelValue)

	if !sc.probeSuccess {
		return
	}

	// --- Collect Port Statistics ---
	if sc.portStats != nil {
		for _, port := range sc.portStats.Ports {
			ch <- prometheus.MustNewConstMetric(
				sc.descs.portState, prometheus.GaugeValue,
				stateToFloat(port.State), port.Name, sc.targetLabelValue,
			)
			ch <- prometheus.MustNewConstMetric(
				sc.descs.portLinkStatus, prometheus.GaugeValue,
				linkStatusToFloat(port.LinkStatus), port.Name, sc.targetLabelValue,
			)
			ch <- prometheus.MustNewConstMetric(
				sc.descs.portTxGoodPkt, prometheus.CounterValue,
				float64(port.TxGoodPkt), port.Name, sc.targetLabelValue,
			)
			ch <- prometheus.MustNewConstMetric(
				sc.descs.portTxBadPkt, prometheus.CounterValue,
				float64(port.TxBadPkt), port.Name, sc.targetLabelValue,
			)
			ch <- prometheus.MustNewConstMetric(
				sc.descs.portRxGoodPkt, prometheus.CounterValue,
				float64(port.RxGoodPkt), port.Name, sc.targetLabelValue,
			)
			ch <- prometheus.MustNewConstMetric(
				sc.descs.portRxBadPkt, prometheus.CounterValue,
				float64(port.RxBadPkt), port.Name, sc.targetLabelValue,
			)
		}
	}

	if sc.stpStats != nil {
		for _, port := range sc.stpStats.Ports {
			var stateVal float64
			switch port.State {
			case "Disabled":
				stateVal = 0
			case "Blocking":
				stateVal = 1
			case "Forwarding":
				stateVal = 2
			default:
				stateVal = -1
			}

			ch <- prometheus.MustNewConstMetric(
				sc.descs.portRSTPState, prometheus.GaugeValue,
				stateVal, port.Name, port.Role, sc.targetLabelValue,
			)
			ch <- prometheus.MustNewConstMetric(
				sc.descs.portRSTPCost, prometheus.GaugeValue,
				float64(port.PathCost), port.Name, port.Role, sc.targetLabelValue,
			)
		}
	}
}

type MetricDescriptions struct {
	probeSuccess         *prometheus.Desc
	probeDurationSeconds *prometheus.Desc
	portState            *prometheus.Desc
	portLinkStatus       *prometheus.Desc
	portTxGoodPkt        *prometheus.Desc
	portTxBadPkt         *prometheus.Desc
	portRxGoodPkt        *prometheus.Desc
	portRxBadPkt         *prometheus.Desc
	portRSTPState        *prometheus.Desc
	portRSTPCost         *prometheus.Desc
}

func newMetricDescriptions() *MetricDescriptions {
	targetLabel := "target"
	portLabel := "port"
	roleLabel := "role"

	return &MetricDescriptions{
		probeSuccess: prometheus.NewDesc(
			"probe_success",
			"Displays whether or not the probe was a success",
			[]string{targetLabel}, nil,
		),
		probeDurationSeconds: prometheus.NewDesc(
			"probe_duration_seconds",
			"Returns how long the probe took to complete in seconds",
			[]string{targetLabel}, nil,
		),
		portState: prometheus.NewDesc(
			"switch_port_state",
			"State of the port (1=Enable, 0=Disable)",
			[]string{portLabel, targetLabel}, nil,
		),
		portLinkStatus: prometheus.NewDesc(
			"switch_port_link_status",
			"Link status of the port (1=Up, 0=Down)",
			[]string{portLabel, targetLabel}, nil,
		),
		portTxGoodPkt: prometheus.NewDesc(
			"switch_port_transmit_packets_good_total",
			"Number of good packets transmitted on the port",
			[]string{portLabel, targetLabel}, nil,
		),
		portTxBadPkt: prometheus.NewDesc(
			"switch_port_transmit_packets_bad_total",
			"Number of bad packets transmitted on the port",
			[]string{portLabel, targetLabel}, nil,
		),
		portRxGoodPkt: prometheus.NewDesc(
			"switch_port_receive_packets_good_total",
			"Number of good packets received on the port",
			[]string{portLabel, targetLabel}, nil,
		),
		portRxBadPkt: prometheus.NewDesc(
			"switch_port_receive_packets_bad_total",
			"Number of bad packets received on the port",
			[]string{portLabel, targetLabel}, nil,
		),
		portRSTPState: prometheus.NewDesc(
			"switch_port_rstp_state",
			"RSTP state of the port (0=Disabled, 1=Blocking, 2=Forwarding)",
			[]string{portLabel, roleLabel, targetLabel}, nil,
		),
		portRSTPCost: prometheus.NewDesc(
			"switch_port_rstp_path_cost",
			"RSTP path cost of the port",
			[]string{portLabel, roleLabel, targetLabel}, nil,
		),
	}
}

var (
	probeErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "switch_exporter_probe_errors_total",
			Help: "Total number of errors encountered during probes, per target.",
		},
		[]string{"target"},
	)
)

// Structure for Prometheus HTTP SD targets
type HttpSdTargetGroup struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}
