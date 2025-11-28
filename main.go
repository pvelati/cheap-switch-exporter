package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
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
	Address  string `yaml:"address"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	PollRate int    `yaml:"poll_rate_seconds"`
	Timeout  int    `yaml:"timeout_seconds"`
}

type Port struct {
	Name       string `json:"port"`
	State      string `json:"state"`
	LinkStatus string `json:"link_status"`
	TxGoodPkt  uint64 `json:"tx_good_pkt"`
	TxBadPkt   uint64 `json:"tx_bad_pkt"`
	RxGoodPkt  uint64 `json:"rx_good_pkt"`
	RxBadPkt   uint64 `json:"rx_bad_pkt"`
}

type PortStatistics struct {
	Ports []Port `json:"port_statistics"`
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
			c.portTxGoodPkt, prometheus.CounterValue,
			float64(port.TxGoodPkt), port.Name,
		)
		ch <- prometheus.MustNewConstMetric(
			c.portTxBadPkt, prometheus.CounterValue,
			float64(port.TxBadPkt), port.Name,
		)
		ch <- prometheus.MustNewConstMetric(
			c.portRxGoodPkt, prometheus.CounterValue,
			float64(port.RxGoodPkt), port.Name,
		)
		ch <- prometheus.MustNewConstMetric(
			c.portRxBadPkt, prometheus.CounterValue,
			float64(port.RxBadPkt), port.Name,
		)
	}

	duration := time.Since(start).Seconds()
	c.lastScrapeDuration.Set(duration)
}

func main() {
	// Read configuration
	config, err := readConfig("config.yaml")
	if err != nil {
		log.Fatalf("Error reading configuration: %v", err)
	}

	// Set default values if not specified
	if config.PollRate == 0 {
		config.PollRate = 10 // Default 10 seconds
	}
	if config.Timeout == 0 {
		config.Timeout = 5 // Default 5 seconds
	}

	// Validate configuration
	if config.Address == "" || config.Username == "" || config.Password == "" {
		log.Fatal("Missing required configuration fields")
	}

	// Create custom collector
	collector := NewPortStatsCollector(config)
	prometheus.MustRegister(collector)

	// Start Prometheus HTTP server
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		log.Println("Starting Prometheus exporter on: 8080/metrics")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Graceful shutdown handling
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	<-stop
	log.Println("Shutting down...")
}

func fetchPortStatistics(config Config) (PortStatistics, error) {
	baseURL := "http://" + config.Address + "/port.cgi"
	params := url.Values{}
	params.Set("page", "stats")

	formParams := url.Values{}
	formParams.Set("username", config.Username)
	formParams.Set("password", config.Password)
	formParams.Set("language", "EN")
	formParams.Set("Response", getMD5Hash(config.Username+config.Password))

	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
	}

	req, err := http.NewRequest("GET", baseURL, strings.NewReader(formParams.Encode()))
	log.Printf("Request: %+v", req)
	if err != nil {
		return PortStatistics{}, fmt.Errorf("error creating request: %w", err)
	}

	cookieValue := getMD5Hash(config.Username + config.Password)
	req.AddCookie(&http.Cookie{Name: "admin", Value: cookieValue})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// With KeepLink KP-9000-9XHML-X, the Referer header is required or the response will be empty
	req.Header.Set("Referer", "http://"+config.Address+"/menu.cgi")
	req.URL.RawQuery = params.Encode()

	resp, err := client.Do(req)
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

	doc.Find("table").Find("tr").Each(func(i int, s *goquery.Selection) {

		if i != 0 {
			port := Port{}
			s.Find("td").Each(func(j int, td *goquery.Selection) {

				cellValue := strings.TrimSpace(td.Text())
				// With KeepLink KP-9000-9XHML-X, some values are unexpectedly prefixed with "0-"
				cellValue = strings.TrimPrefix(cellValue, "0-")

				switch j {
				case 0:
					port.Name = td.Text()
				case 1:
					port.State = td.Text()
				case 2:
					port.LinkStatus = td.Text()
				case 3:
					val, _ := strconv.ParseUint(cellValue, 10, 64)
					port.TxGoodPkt = val
				case 4:
					val, _ := strconv.ParseUint(cellValue, 10, 64)
					port.TxBadPkt = val
				case 5:
					val, _ := strconv.ParseUint(cellValue, 10, 64)
					port.RxGoodPkt = val
				case 6:
					val, _ := strconv.ParseUint(cellValue, 10, 64)
					port.RxBadPkt = val
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
