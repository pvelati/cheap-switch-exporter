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
	Address         string `yaml:"address"`
	Username        string `yaml:"username"`
	Password        string `yaml:"password"`
	AuthMethod      string `yaml:"auth_method"` // "userpass" or "cookie"
	PollRateSeconds int    `yaml:"poll_rate_seconds"`
	TimeoutSeconds  int    `yaml:"timeout_seconds"`
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
	client             *http.Client
	// Fields specific to cookie authentication
	cookieAuth struct {
		cookie   *http.Cookie
		lastAuth time.Time
	}
}

func NewPortStatsCollector(config Config) *PortStatsCollector {
	// Validate authentication method
	if config.AuthMethod != "userpass" && config.AuthMethod != "cookie" {
		log.Printf("Invalid auth_method %q, defaulting to userpass", config.AuthMethod)
		config.AuthMethod = "userpass"
	}

	return &PortStatsCollector{
		config: config,
		portState: prometheus.NewDesc(
			"port_state",
			"State of the port (1 = Enable, 0 = Disable)",
			[]string{"port"}, nil,
		),
		portLinkStatus: prometheus.NewDesc(
			"port_link_status",
			"Link status of the port (1 = Link Up, 0 = Link Down)",
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
		client: &http.Client{
			Timeout: time.Duration(config.TimeoutSeconds) * time.Second,
		},
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

// authenticate performs cookie-based authentication and returns any error
func (c *PortStatsCollector) authenticate() error {
	// Check if we have a valid cookie less than 5 minutes old
	if c.cookieAuth.cookie != nil && time.Since(c.cookieAuth.lastAuth) < 5*time.Minute {
		return nil
	}

	loginURL := fmt.Sprintf("http://%s/login.cgi", c.config.Address)

	req, err := http.NewRequest("GET", loginURL, nil)
	if err != nil {
		return fmt.Errorf("error creating auth request: %w", err)
	}

	q := req.URL.Query()
	q.Add("username", c.config.Username)
	q.Add("password", c.config.Password)
	req.URL.RawQuery = q.Encode()

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("error during authentication: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed with status: %d", resp.StatusCode)
	}

	for _, cookie := range resp.Cookies() {
		c.cookieAuth.cookie = cookie
		c.cookieAuth.lastAuth = time.Now()
		return nil
	}

	return fmt.Errorf("no authentication cookie received")
}

func (c *PortStatsCollector) Collect(ch chan<- prometheus.Metric) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	start := time.Now()
	stats, err := c.fetchPortStatistics()
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
	if config.PollRateSeconds == 0 {
		config.PollRateSeconds = 10 // Default 10 seconds
	}
	if config.TimeoutSeconds == 0 {
		config.TimeoutSeconds = 5 // Default 5 seconds
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
		log.Println("Starting Prometheus exporter on :8080/metrics")
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

// fetchPortStatistics retrieves port statistics using the configured authentication method
func (c *PortStatsCollector) fetchPortStatistics() (PortStatistics, error) {
	var req *http.Request
	var err error

	statsURL := fmt.Sprintf("http://%s/port.cgi", c.config.Address)

	if c.config.AuthMethod == "cookie" {
		// Cookie-based authentication
		if err := c.authenticate(); err != nil {
			return PortStatistics{}, fmt.Errorf("authentication failed: %w", err)
		}

		req, err = http.NewRequest("GET", statsURL, nil)
		if err != nil {
			return PortStatistics{}, fmt.Errorf("error creating stats request: %w", err)
		}

		req.AddCookie(c.cookieAuth.cookie)
	} else {
		// Username/password authentication
		formParams := url.Values{}
		formParams.Set("username", c.config.Username)
		formParams.Set("password", c.config.Password)
		formParams.Set("language", "EN")
		formParams.Set("Response", getMD5Hash(c.config.Username+c.config.Password))

		req, err = http.NewRequest("GET", statsURL, strings.NewReader(formParams.Encode()))
		if err != nil {
			return PortStatistics{}, fmt.Errorf("error creating request: %w", err)
		}

		cookieValue := getMD5Hash(c.config.Username + c.config.Password)
		req.AddCookie(&http.Cookie{Name: "admin", Value: cookieValue})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// Common parameters for both authentication methods
	q := req.URL.Query()
	q.Add("page", "stats")
	req.URL.RawQuery = q.Encode()

	resp, err := c.client.Do(req)
	if err != nil {
		return PortStatistics{}, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return PortStatistics{}, fmt.Errorf("stats request failed with status: %d", resp.StatusCode)
	}

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
