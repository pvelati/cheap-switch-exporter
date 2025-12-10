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
	PoE      int    `yaml:"PoE"`
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

type PortPoE struct {
	Name    string  `json:"port"`
	State   string  `json:"state"`
	Power   string  `json:"power"` // "On" / "Off"
	Type    string  `json:"type"`  // "-" or "Class1"/"Class2"/...
	Watts   float64 `json:"watts"`
	Voltage float64 `json:"voltage"`
	Current float64 `json:"current"`
}

type PoEStatistics struct {
	Ports []PortPoE `json:"ports"`
}

type PoESystem struct {
	Consumption float64 `json:"consumption"`
}

type PortStatsCollector struct {
	config               Config
	portState            *prometheus.Desc
	portLinkStatus       *prometheus.Desc
	portTxGoodPkt        *prometheus.Desc
	portTxBadPkt         *prometheus.Desc
	portRxGoodPkt        *prometheus.Desc
	portRxBadPkt         *prometheus.Desc
	lastScrapeDuration   prometheus.Gauge
	scrapeErrorsTotal    prometheus.Counter
	poeSystemConsumption *prometheus.Desc
	poeState             *prometheus.Desc
	poePower             *prometheus.Desc
	poeType              *prometheus.Desc
	poeWatts             *prometheus.Desc
	poeVoltage           *prometheus.Desc
	poeCurrent           *prometheus.Desc
	mutex                sync.Mutex
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
		poeSystemConsumption: prometheus.NewDesc(
			"poe_system_consumption_watts",
			"Total PoE consumption in watts",
			nil, nil,
		),
		poeState: prometheus.NewDesc(
			"poe_port_state",
			"State of the PoE port (1=Enable, 0=Disable)",
			[]string{"port"}, nil,
		),
		poePower: prometheus.NewDesc(
			"poe_port_power_on",
			"PoE port power on/off (1=On, 0=Off)",
			[]string{"port"}, nil,
		),
		poeType: prometheus.NewDesc(
			"poe_port_type",
			"PoE port type class (1-4, 0=none)",
			[]string{"port"}, nil,
		),
		poeWatts: prometheus.NewDesc(
			"poe_port_watts",
			"PoE port power consumption in watts",
			[]string{"port"}, nil,
		),
		poeVoltage: prometheus.NewDesc(
			"poe_port_voltage",
			"PoE port voltage in volts",
			[]string{"port"}, nil,
		),
		poeCurrent: prometheus.NewDesc(
			"poe_port_current_ma",
			"PoE port current in mA",
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

	poeSystem, err := fetchPoESystem(c.config)
	if err != nil {
		c.scrapeErrorsTotal.Inc()
		log.Printf("Error fetching PoE system: %v", err)
	} else {
		ch <- prometheus.MustNewConstMetric(
			c.poeSystemConsumption,
			prometheus.GaugeValue,
			poeSystem.Consumption,
		)
	}

	poeStats, err := fetchPoEPorts(c.config)
	if err != nil {
		c.scrapeErrorsTotal.Inc()
		log.Printf("Error fetching PoE port statistics: %v", err)
		return
	}

	for _, port := range poeStats.Ports {
		ch <- prometheus.MustNewConstMetric(
			c.poeState, prometheus.GaugeValue,
			stateToFloat(port.State), port.Name,
		)
		ch <- prometheus.MustNewConstMetric(
			c.poePower, prometheus.GaugeValue,
			powerToFloat(port.Power), port.Name,
		)
		ch <- prometheus.MustNewConstMetric(
			c.poeType, prometheus.GaugeValue,
			typeToFloat(port.Type), port.Name,
		)
		ch <- prometheus.MustNewConstMetric(
			c.poeWatts, prometheus.GaugeValue,
			port.Watts, port.Name,
		)
		ch <- prometheus.MustNewConstMetric(
			c.poeVoltage, prometheus.GaugeValue,
			port.Voltage, port.Name,
		)
		ch <- prometheus.MustNewConstMetric(
			c.poeCurrent, prometheus.GaugeValue,
			port.Current, port.Name,
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
	if err != nil {
		return PortStatistics{}, fmt.Errorf("error creating request: %w", err)
	}

	cookieValue := getMD5Hash(config.Username + config.Password)
	req.AddCookie(&http.Cookie{Name: "admin", Value: cookieValue})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", fmt.Sprintf("http://%s/menu.cgi", config.Address))
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

func fetchPoESystem(config Config) (PoESystem, error) {
	baseURL := "http://" + config.Address + "/pse_system.cgi"
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
	if err != nil {
		return PoESystem{}, fmt.Errorf("error creating request: %w", err)
	}

	cookieValue := getMD5Hash(config.Username + config.Password)
	req.AddCookie(&http.Cookie{Name: "admin", Value: cookieValue})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", fmt.Sprintf("http://%s/menu.cgi", config.Address))
	req.URL.RawQuery = params.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return PoESystem{}, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return PoESystem{}, fmt.Errorf("error parsing HTML: %w", err)
	}

	return parsePoESystem(doc)
}

func fetchPoEPorts(config Config) (PoEStatistics, error) {
	baseURL := "http://" + config.Address + "/pse_port.cgi"
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
	if err != nil {
		return PoEStatistics{}, fmt.Errorf("error creating request: %w", err)
	}

	cookieValue := getMD5Hash(config.Username + config.Password)
	req.AddCookie(&http.Cookie{Name: "admin", Value: cookieValue})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", fmt.Sprintf("http://%s/menu.cgi", config.Address))
	req.URL.RawQuery = params.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return PoEStatistics{}, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return PoEStatistics{}, fmt.Errorf("error parsing HTML: %w", err)
	}

	return parsePoEPorts(doc)
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

func parsePoESystem(doc *goquery.Document) (PoESystem, error) {
	var system PoESystem

	val := doc.Find(`input[name="pse_con_pwr"]`).AttrOr("value", "")

	if val == "" {
		return system, fmt.Errorf("pse_con_pwr value not found")
	}

	cons, err := strconv.ParseFloat(val, 64)
	if err != nil {
		return system, fmt.Errorf("invalid consumption value: %w", err)
	}

	system.Consumption = cons
	return system, nil
}

func parsePoEPorts(doc *goquery.Document) (PoEStatistics, error) {
	var stats PoEStatistics

	doc.Find("table tbody tr").Each(func(i int, s *goquery.Selection) {
		if s.Find("th").Length() > 0 {
			return
		}

		tds := s.ChildrenFiltered("td")
		if tds.Length() != 7 {
			return
		}

		var port PortPoE
		tds.Each(func(j int, td *goquery.Selection) {
			text := strings.TrimSpace(td.Text())
			switch j {
			case 0:
				port.Name = text
			case 1:
				port.State = text
			case 2:
				port.Power = text
			case 3:
				port.Type = text
			case 4:
				port.Watts = parseFloatOrZero(text)
			case 5:
				port.Voltage = parseFloatOrZero(text)
			case 6:
				port.Current = parseFloatOrZero(text)
			}
		})

		if port.Name != "" {
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

func parseFloatOrZero(s string) float64 {
	if s == "-" || s == "" {
		return 0
	}
	val, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return val
}

func powerToFloat(s string) float64 {
	switch s {
	case "On":
		return 1
	case "Off":
		return 0
	default:
		return 0
	}
}

func typeToFloat(s string) float64 {
	switch s {
	case "Class1":
		return 1
	case "Class2":
		return 2
	case "Class3":
		return 3
	case "Class4":
		return 4
	default:
		return 0
	}
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
