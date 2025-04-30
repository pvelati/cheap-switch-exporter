package main

import (
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen   string `yaml:"listen"`
	Address  string `yaml:"address"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Timeout  int    `yaml:"timeout_seconds"`
	STP      bool   `yaml:"stp"`
}

type Port struct {
	Name       string `json:"port"`
	State      string `json:"state"`
	LinkStatus string `json:"link_status"`
	TxGoodPkt  int    `json:"tx_good_pkt"`
	TxBadPkt   int    `json:"tx_bad_pkt"`
	RxGoodPkt  int    `json:"rx_good_pkt"`
	RxBadPkt   int    `json:"rx_bad_pkt"`
}

type PortStatistics struct {
	Ports []Port `json:"port_statistics"`
}

type STPPort struct {
	Name     string `json:"port"`
	State    string `json:"state"`
	Role     string `json:"role"`
	PathCost int    `json:"path_cost"`
}

type STPPortStatistics struct {
	Ports []STPPort `json:"stp_port_statistics"`
}

type PortStatsCollector struct {
	config             Config
	portState          *prometheus.Desc
	portLinkStatus     *prometheus.Desc
	portTxGoodPkt      *prometheus.Desc
	portTxBadPkt       *prometheus.Desc
	portRxGoodPkt      *prometheus.Desc
	portRxBadPkt       *prometheus.Desc
	lastScrapeDuration prometheus.Gauge
	scrapeErrorsTotal  prometheus.Counter
	mutex              sync.Mutex
}

type STPPortStatsCollector struct {
	config             Config
	portRSTPState      *prometheus.Desc
	portRSTPCost       *prometheus.Desc
	lastScrapeDuration prometheus.Gauge
	scrapeErrorsTotal  prometheus.Counter
	mutex              sync.Mutex
}

func NewSTPPortStatsCollector(config Config) *STPPortStatsCollector {
	return &STPPortStatsCollector{
		config: config,
		portRSTPState: prometheus.NewDesc(
			"port_rstp_state",
			"RSTP state of the port (0=Disabled, 1=Blocking, 2=Forwarding)",
			[]string{"port", "role"}, nil,
		),
		portRSTPCost: prometheus.NewDesc(
			"port_rstp_cost",
			"RSTP path cost of the port",
			[]string{"port", "role"}, nil,
		),
		lastScrapeDuration: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "exporter_stp_last_scrape_duration_seconds",
			Help: "Duration of the last scrape",
		}),
		scrapeErrorsTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "exporter_stp_scrape_errors_total",
			Help: "Total number of scrape errors",
		}),
	}
}

func NewPortStatsCollector(config Config) *PortStatsCollector {
	return &PortStatsCollector{
		config: config,
		portState: prometheus.NewDesc(
			"port_state",
			"State of the port",
			[]string{"port"}, nil,
		),
		portLinkStatus: prometheus.NewDesc(
			"port_link_status",
			"Link status of the port",
			[]string{"port"}, nil,
		),
		portTxGoodPkt: prometheus.NewDesc(
			"port_tx_good_pkt",
			"Number of good packets transmitted on the port",
			[]string{"port"}, nil,
		),
		portTxBadPkt: prometheus.NewDesc(
			"port_tx_bad_pkt",
			"Number of bad packets transmitted on the port",
			[]string{"port"}, nil,
		),
		portRxGoodPkt: prometheus.NewDesc(
			"port_rx_good_pkt",
			"Number of good packets received on the port",
			[]string{"port"}, nil,
		),
		portRxBadPkt: prometheus.NewDesc(
			"port_rx_bad_pkt",
			"Number of bad packets received on the port",
			[]string{"port"}, nil,
		),
		lastScrapeDuration: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "exporter_last_scrape_duration_seconds",
			Help: "Duration of the last scrape",
		}),
		scrapeErrorsTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "exporter_scrape_errors_total",
			Help: "Total number of scrape errors",
		}),
	}
}

func (c *PortStatsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.portState
	ch <- c.portLinkStatus
	ch <- c.portTxGoodPkt
	ch <- c.portTxBadPkt
	ch <- c.portRxGoodPkt
	ch <- c.portRxBadPkt
}

func (c *STPPortStatsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.portRSTPState
	ch <- c.portRSTPCost
}

func (c *PortStatsCollector) Collect(ch chan<- prometheus.Metric) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	start := time.Now()
	stats, err := fetchPortStatistics(c.config)
	if err != nil {
		c.scrapeErrorsTotal.Inc()
		log.Printf("Error fetching port statistics: %v", err)
		return
	}

	for _, port := range stats.Ports {
		ch <- prometheus.MustNewConstMetric(
			c.portState, prometheus.GaugeValue,
			stateToFloat(port.State), port.Name,
		)
		ch <- prometheus.MustNewConstMetric(
			c.portLinkStatus, prometheus.GaugeValue,
			linkStatusToFloat(port.LinkStatus), port.Name,
		)
		ch <- prometheus.MustNewConstMetric(
			c.portTxGoodPkt, prometheus.GaugeValue,
			float64(port.TxGoodPkt), port.Name,
		)
		ch <- prometheus.MustNewConstMetric(
			c.portTxBadPkt, prometheus.GaugeValue,
			float64(port.TxBadPkt), port.Name,
		)
		ch <- prometheus.MustNewConstMetric(
			c.portRxGoodPkt, prometheus.GaugeValue,
			float64(port.RxGoodPkt), port.Name,
		)
		ch <- prometheus.MustNewConstMetric(
			c.portRxBadPkt, prometheus.GaugeValue,
			float64(port.RxBadPkt), port.Name,
		)
	}

	duration := time.Since(start).Seconds()
	c.lastScrapeDuration.Set(duration)
}

func (c *STPPortStatsCollector) Collect(ch chan<- prometheus.Metric) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	start := time.Now()
	stats, err := fetchSTPPortStatistics(c.config)
	if err != nil {
		c.scrapeErrorsTotal.Inc()
		log.Printf("Error fetching STP port statistics: %v", err)
		return
	}

	for _, port := range stats.Ports {
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
			c.portRSTPState,
			prometheus.GaugeValue,
			stateVal,
			port.Name, port.Role,
		)

		ch <- prometheus.MustNewConstMetric(
			c.portRSTPCost,
			prometheus.GaugeValue,
			float64(port.PathCost),
			port.Name, port.Role,
		)
	}

	duration := time.Since(start).Seconds()
	c.lastScrapeDuration.Set(duration)
}

func performHealthCheck(host, port string) {
	if host == "0.0.0.0" {
		host = "127.0.0.1"
	}

	targetURL := fmt.Sprintf("http://%s:%s/metrics", host, port)

	client := http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		log.Printf("Health check failed: Error connecting to %s: %v", targetURL, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		log.Printf("Health check failed: Received non-OK status code %d from %s", resp.StatusCode, targetURL)
		os.Exit(1)
	}
	os.Exit(0)
}

func main() {
	configFile := flag.String("config.file", "config.yaml", "Path to configuration file.")
	healthcheck := flag.Bool("healthcheck", false, "Perform a health check against the configured listen address and exit.")
	flag.Parse()

	config, err := readConfig(*configFile)
	if err != nil {
		log.Fatalf("Fatal: Error reading configuration from %s: %v", *configFile, err)
	}

	// Set default values if not specified
	if config.Timeout == 0 {
		config.Timeout = 5
	}
	if config.Listen == "" {
		config.Listen = ":8080"
	}

	if config.Address == "" || config.Username == "" || config.Password == "" {
		log.Fatal("Missing required configuration fields")
	}

	host, port, err := net.SplitHostPort(config.Listen)
	if err != nil {
		log.Fatalf("Invalid listen address '%s' used: %v", config.Listen, err)
	}

	if *healthcheck {
		performHealthCheck(host, port)
		return
	}

	log.Printf("Configuration read successfully from %s", *configFile)

	// Create custom collector
	collector := NewPortStatsCollector(config)
	prometheus.MustRegister(collector)

	if config.STP {
		stpCollector := NewSTPPortStatsCollector(config)
		prometheus.MustRegister(stpCollector)
	}

	// Start Prometheus HTTP server
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		log.Printf("Starting Prometheus exporter on %s/metrics", config.Listen)
		if err := http.ListenAndServe(config.Listen, nil); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Graceful shutdown handling
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	<-stop
	log.Println("Shutting down...")
}

func makeRequest(config Config, path string) (*http.Response, error) {
	base, err := url.Parse("http://" + config.Address)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	rel, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}

	fullURL := base.ResolveReference(rel)

	formParams := url.Values{}
	formParams.Set("username", config.Username)
	formParams.Set("password", config.Password)
	formParams.Set("language", "EN")
	formParams.Set("Response", getMD5Hash(config.Username+config.Password))

	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
	}

	req, err := http.NewRequest("GET", fullURL.String(), strings.NewReader(formParams.Encode()))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	cookieValue := getMD5Hash(config.Username + config.Password)
	req.AddCookie(&http.Cookie{Name: "admin", Value: cookieValue})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	return resp, err
}

func fetchSTPPortStatistics(config Config) (STPPortStatistics, error) {
	resp, err := makeRequest(config, "/loop.cgi?page=stp_port")
	if err != nil {
		return STPPortStatistics{}, fmt.Errorf("error sending STP request: %w", err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return STPPortStatistics{}, fmt.Errorf("error parsing STP HTML: %w", err)
	}

	return parseSTPPortStatistics(doc)
}

func fetchPortStatistics(config Config) (PortStatistics, error) {
	resp, err := makeRequest(config, "/port.cgi?page=stats")
	if err != nil {
		return PortStatistics{}, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return PortStatistics{}, fmt.Errorf("error parsing HTML: %w", err)
	}

	return parsePortStatistics(doc)
}

func parsePortStatistics(doc *goquery.Document) (PortStatistics, error) {
	var stats PortStatistics

	doc.Find("table tr").Each(func(i int, s *goquery.Selection) {
		if i != 0 {
			port := Port{}
			s.Find("td").Each(func(j int, td *goquery.Selection) {
				switch j {
				case 0:
					port.Name = td.Text()
				case 1:
					port.State = td.Text()
				case 2:
					port.LinkStatus = td.Text()
				case 3:
					port.TxGoodPkt, _ = strconv.Atoi(strings.TrimSpace(td.Text()))
				case 4:
					port.TxBadPkt, _ = strconv.Atoi(strings.TrimSpace(td.Text()))
				case 5:
					port.RxGoodPkt, _ = strconv.Atoi(strings.TrimSpace(td.Text()))
				case 6:
					port.RxBadPkt, _ = strconv.Atoi(strings.TrimSpace(td.Text()))
				}
			})
			stats.Ports = append(stats.Ports, port)
		}
	})

	return stats, nil
}

func parseSTPPortStatistics(doc *goquery.Document) (STPPortStatistics, error) {
	var stats STPPortStatistics

	doc.Find("table tr").Each(func(i int, s *goquery.Selection) {
		if i > 3 {
			port := STPPort{}
			s.Find("td").Each(func(j int, td *goquery.Selection) {
				switch j {
				case 0:
					port.Name = td.Text()
				case 1:
					port.State = td.Text()
				case 2:
					port.Role = td.Text()
				case 4:
					port.PathCost, _ = strconv.Atoi(strings.TrimSpace(td.Text()))
				}
			})
			stats.Ports = append(stats.Ports, port)
		}
	})

	return stats, nil
}

func stateToFloat(state string) float64 {
	return map[string]float64{
		"Enable":  1.0,
		"Disable": 0.0,
	}[state]
}

func linkStatusToFloat(status string) float64 {
	return map[string]float64{
		"Link Up":   1.0,
		"Link Down": 0.0,
	}[status]
}

func getMD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

func readConfig(filename string) (Config, error) {
	var config Config

	data, err := os.ReadFile(filename)
	if err != nil {
		return config, err
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return config, err
	}

	return config, nil
}
