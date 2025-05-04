package main

import (
	"context" // Added import
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
	"strings" // Keep sync import for potential future use, though not strictly needed now
	"syscall"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

// --- Configuration Structures (Unchanged) ---

type SwitchConfig struct {
	Name           string `yaml:"name"`
	Address        string `yaml:"address"`
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	TimeoutSeconds int    `yaml:"timeout_seconds"`
	STP            bool   `yaml:"stp"`
}

type AppConfig struct {
	Listen                string                  `yaml:"listen"`
	DefaultTimeoutSeconds int                     `yaml:"default_timeout_seconds"`
	Targets               []SwitchConfig          `yaml:"targets"`
	TargetsMap            map[string]SwitchConfig `yaml:"-"` // Ignore during YAML unmarshal
}

// --- Data Structures for Parsing (Unchanged) ---

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

// --- Prometheus Metric Descriptions (Unchanged) ---

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

// --- Global Metrics for Exporter Itself (Unchanged) ---

var (
	probeErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "switch_exporter_probe_errors_total",
			Help: "Total number of errors encountered during probes, per target.",
		},
		[]string{"target"},
	)
)

// --- Temporary Collector for On-Demand Scrapes ---

type switchScrapeCollector struct {
	targetLabelValue string
	descs            *MetricDescriptions
	portStats        *PortStatistics    // Pointer to allow nil if fetch fails
	stpStats         *STPPortStatistics // Pointer to allow nil if fetch fails or not enabled
	probeDuration    float64
	probeSuccess     bool
}

// Describe implements prometheus.Collector.
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

// Collect implements prometheus.Collector.
func (sc *switchScrapeCollector) Collect(ch chan<- prometheus.Metric) {
	// Report probe success and duration first
	successValue := 0.0
	if sc.probeSuccess {
		successValue = 1.0
	}
	ch <- prometheus.MustNewConstMetric(sc.descs.probeSuccess, prometheus.GaugeValue, successValue, sc.targetLabelValue)
	ch <- prometheus.MustNewConstMetric(sc.descs.probeDurationSeconds, prometheus.GaugeValue, sc.probeDuration, sc.targetLabelValue)

	// Only report device metrics if the probe was successful overall
	// (Alternatively, you could report partial data even on probe failure, adjust logic as needed)
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

	// --- Collect STP Statistics ---
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

// --- Core Logic (fetch*, parse*, readConfig, makeRequest are mostly unchanged) ---

func readConfig(filename string) (AppConfig, error) {
	var config AppConfig
	config.TargetsMap = make(map[string]SwitchConfig) // Initialize the map

	data, err := os.ReadFile(filename)
	if err != nil {
		return config, fmt.Errorf("failed to read config file %s: %w", filename, err)
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return config, fmt.Errorf("failed to unmarshal config YAML: %w", err)
	}

	// Set defaults and validate targets
	if config.DefaultTimeoutSeconds <= 0 {
		config.DefaultTimeoutSeconds = 10
	}
	if config.Listen == "" {
		config.Listen = ":8080"
	}
	if len(config.Targets) == 0 {
		return config, fmt.Errorf("no targets defined in configuration")
	}

	validTargets := make([]SwitchConfig, 0, len(config.Targets))
	for i := range config.Targets { // Iterate using index to modify original slice elements if needed
		target := &config.Targets[i] // Use pointer for potential modifications

		if target.Address == "" {
			log.Printf("Warning: Skipping target entry %d: missing required 'address' field", i)
			continue // Skip this invalid target
		}
		if target.Username == "" {
			log.Printf("Warning: Skipping target '%s' (%s): missing required 'username' field", target.Name, target.Address)
			continue
		}
		if target.Password == "" {
			log.Printf("Warning: Skipping target '%s' (%s): missing required 'password' field", target.Name, target.Address)
			continue
		}

		// Use default timeout if target-specific one isn't set or invalid
		if target.TimeoutSeconds <= 0 {
			target.TimeoutSeconds = config.DefaultTimeoutSeconds
		}

		// Populate the map for quick lookup
		if _, exists := config.TargetsMap[target.Address]; exists {
			log.Printf("Warning: Duplicate target address '%s' found in config. Last definition will be used.", target.Address)
		}
		config.TargetsMap[target.Address] = *target  // Add the validated/updated target to the map
		validTargets = append(validTargets, *target) // Add to a new list of only valid targets
	}
	config.Targets = validTargets // Replace original targets with only the valid ones

	if len(config.TargetsMap) == 0 {
		return config, fmt.Errorf("no valid targets found in configuration after validation")
	}

	return config, nil
}

// makeRequest, fetchPortStatistics, fetchSTPPortStatistics,
// parsePortStatistics, parseSTPPortStatistics remain the same as in the previous corrected version
// (Ensure they log errors with target identifiers)
// ... (insert the unchanged functions here for completeness) ...
func makeRequest(config SwitchConfig, path string) (*http.Response, error) {
	base, err := url.Parse("http://" + config.Address)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL for target %s: %w", config.Address, err)
	}

	rel, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("invalid path for target %s: %w", config.Address, err)
	}

	fullURL := base.ResolveReference(rel)

	formParams := url.Values{}
	formParams.Set("username", config.Username)
	formParams.Set("password", config.Password)
	formParams.Set("language", "EN")
	formParams.Set("Response", getMD5Hash(config.Username+config.Password))

	client := &http.Client{
		Timeout: time.Duration(config.TimeoutSeconds) * time.Second, // Use effective timeout
	}

	req, err := http.NewRequest("GET", fullURL.String(), strings.NewReader(formParams.Encode()))
	if err != nil {
		return nil, fmt.Errorf("error creating request for target %s: %w", config.Address, err)
	}

	cookieValue := getMD5Hash(config.Username + config.Password)
	req.AddCookie(&http.Cookie{Name: "admin", Value: cookieValue})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	log.Printf("Probing target %s at path %s", config.Address, path)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error executing request for target %s: %w", config.Address, err)
	}

	return resp, nil
}

func fetchPortStatistics(config SwitchConfig) (PortStatistics, error) {
	resp, err := makeRequest(config, "/port.cgi?page=stats")
	if err != nil {
		return PortStatistics{}, fmt.Errorf("port stats request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return PortStatistics{}, fmt.Errorf("port stats request returned non-OK status %d for target %s: %s", resp.StatusCode, config.Address, string(bodyBytes))
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return PortStatistics{}, fmt.Errorf("error parsing port stats HTML for target %s: %w", config.Address, err)
	}

	return parsePortStatistics(doc)
}

func fetchSTPPortStatistics(config SwitchConfig) (STPPortStatistics, error) {
	resp, err := makeRequest(config, "/loop.cgi?page=stp_port")
	if err != nil {
		return STPPortStatistics{}, fmt.Errorf("STP stats request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return STPPortStatistics{}, fmt.Errorf("STP stats request returned non-OK status %d for target %s: %s", resp.StatusCode, config.Address, string(bodyBytes))
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return STPPortStatistics{}, fmt.Errorf("error parsing STP stats HTML for target %s: %w", config.Address, err)
	}

	return parseSTPPortStatistics(doc)
}

func parsePortStatistics(doc *goquery.Document) (PortStatistics, error) {
	var stats PortStatistics
	var parseErrors []string

	doc.Find("table tr").Each(func(i int, s *goquery.Selection) {
		// Assuming the first row (i=0) is headers
		if i != 0 {
			port := Port{}
			s.Find("td").Each(func(j int, td *goquery.Selection) {
				text := strings.TrimSpace(td.Text())
				var err error
				switch j {
				case 0:
					port.Name = text
				case 1:
					port.State = text
				case 2:
					port.LinkStatus = text
				case 3:
					port.TxGoodPkt, err = strconv.Atoi(text)
					if err != nil {
						parseErrors = append(parseErrors, fmt.Sprintf("row %d, col %d (TxGoodPkt): %v", i, j, err))
					}
				case 4:
					port.TxBadPkt, err = strconv.Atoi(text)
					if err != nil {
						parseErrors = append(parseErrors, fmt.Sprintf("row %d, col %d (TxBadPkt): %v", i, j, err))
					}
				case 5:
					port.RxGoodPkt, err = strconv.Atoi(text)
					if err != nil {
						parseErrors = append(parseErrors, fmt.Sprintf("row %d, col %d (RxGoodPkt): %v", i, j, err))
					}
				case 6:
					port.RxBadPkt, err = strconv.Atoi(text)
					if err != nil {
						parseErrors = append(parseErrors, fmt.Sprintf("row %d, col %d (RxBadPkt): %v", i, j, err))
					}
				}
			})
			// Basic check if we got a port name
			if port.Name != "" {
				stats.Ports = append(stats.Ports, port)
				// Check if the row had any 'td' elements before logging warning
			} else if s.Find("td").Length() > 0 { // CORRECTED LINE
				log.Printf("Skipping row %d in port stats table: No port name found.", i)
			}
		}
	})

	if len(parseErrors) > 0 {
		return stats, fmt.Errorf("parsing port statistics: %s", strings.Join(parseErrors, "; "))
	}
	if len(stats.Ports) == 0 && doc.Find("table tr").Length() > 1 { // Check if table had rows beyond header
		log.Println("Warning: No ports parsed from statistics table, but data rows were present.")
	}
	if len(stats.Ports) == 0 && doc.Find("table tr").Length() <= 1 { // Check if only header or empty
		return stats, fmt.Errorf("no data rows found in port statistics table")
	}
	return stats, nil
}

func parseSTPPortStatistics(doc *goquery.Document) (STPPortStatistics, error) {
	var stats STPPortStatistics
	var parseErrors []string

	doc.Find("table tr").Each(func(i int, s *goquery.Selection) {
		// Adjust index based on actual HTML structure if needed (e.g., skip multiple header rows)
		if i > 3 { // Assuming first row (i=0) is header
			port := STPPort{}
			s.Find("td").Each(func(j int, td *goquery.Selection) {
				text := strings.TrimSpace(td.Text())
				var err error
				switch j {
				case 0:
					port.Name = text
				case 1:
					port.State = text
				case 2:
					port.Role = text
				case 4: // Assuming Path Cost is the 5th column (index 4)
					port.PathCost, err = strconv.Atoi(text)
					if err != nil {
						parseErrors = append(parseErrors, fmt.Sprintf("row %d, col %d (PathCost): %v", i, j, err))
					}
				}
			})
			// Basic check if we got a port name
			if port.Name != "" {
				stats.Ports = append(stats.Ports, port)
				// Check if the row had any 'td' elements before logging warning
			} else if s.Find("td").Length() > 0 { // CORRECTED LINE
				log.Printf("Skipping row %d in STP stats table: No port name found.", i)
			}
		}
	})

	if len(parseErrors) > 0 {
		return stats, fmt.Errorf("parsing STP statistics: %s", strings.Join(parseErrors, "; "))
	}
	if len(stats.Ports) == 0 && doc.Find("table tr").Length() > 1 { // Check if table had rows beyond header
		log.Println("Warning: No ports parsed from STP statistics table, but data rows were present.")
	}
	if len(stats.Ports) == 0 && doc.Find("table tr").Length() <= 1 { // Check if only header or empty
		return stats, fmt.Errorf("no data rows found in STP statistics table")
	}
	return stats, nil
}

// --- HTTP Probe Handler ---

func probeHandler(appConfig AppConfig, descs *MetricDescriptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		target := r.URL.Query().Get("target")
		if target == "" {
			http.Error(w, "'target' parameter is missing", http.StatusBadRequest)
			return
		}

		switchConfig, found := appConfig.TargetsMap[target]
		if !found {
			http.Error(w, fmt.Sprintf("Target '%s' not found in configuration", target), http.StatusNotFound)
			return
		}

		// --- Fetch Data ---
		var portStatsResult *PortStatistics
		var stpStatsResult *STPPortStatistics
		var finalError error // Track if any fetch failed

		portStats, errPort := fetchPortStatistics(switchConfig)
		if errPort != nil {
			log.Printf("Error fetching port metrics for target %s: %v", target, errPort)
			finalError = errPort // Record the error
		} else {
			portStatsResult = &portStats // Store successful result
		}

		if switchConfig.STP {
			stpStats, errSTP := fetchSTPPortStatistics(switchConfig)
			if errSTP != nil {
				log.Printf("Error fetching STP metrics for target %s: %v", target, errSTP)
				if finalError == nil { // Only record if it's the first error
					finalError = errSTP
				}
			} else {
				stpStatsResult = &stpStats // Store successful result
			}
		}

		duration := time.Since(startTime).Seconds()
		success := finalError == nil

		// --- Create and Register Temporary Collector ---
		registry := prometheus.NewRegistry()
		collector := &switchScrapeCollector{
			targetLabelValue: target,
			descs:            descs,
			portStats:        portStatsResult, // Pass potentially nil pointers
			stpStats:         stpStatsResult,  // Pass potentially nil pointers
			probeDuration:    duration,
			probeSuccess:     success,
		}
		registry.MustRegister(collector)

		// Update global error counter if probe failed
		if !success {
			probeErrorsTotal.WithLabelValues(target).Inc()
		}

		// --- Serve Metrics ---
		h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{
			ErrorLog:      log.New(os.Stderr, "", log.LstdFlags),
			ErrorHandling: promhttp.ContinueOnError, // Or PanicOnError based on preference
		})
		h.ServeHTTP(w, r)
		log.Printf("Probe for target %s completed in %.2f seconds (Success: %t)", target, duration, success)
	}
}

// --- Utility Functions (stateToFloat, linkStatusToFloat, getMD5Hash, performHealthCheck - Unchanged) ---
// ... (insert the unchanged functions here for completeness) ...
func stateToFloat(state string) float64 {
	switch strings.ToLower(state) {
	case "enable":
		return 1.0
	case "disable":
		return 0.0
	default:
		log.Printf("Warning: Unknown port state '%s'", state)
		return -1.0
	}
}

func linkStatusToFloat(status string) float64 {
	switch strings.ToLower(status) {
	case "link up":
		return 1.0
	case "link down":
		return 0.0
	default:
		log.Printf("Warning: Unknown link status '%s'", status)
		return -1.0
	}
}

func getMD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

func performHealthCheck(listenAddr string) {
	proto := "http"
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		log.Printf("Health check failed: Could not parse listen address '%s': %v", listenAddr, err)
		os.Exit(1)
	}
	if host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}

	targetURL := fmt.Sprintf("%s://%s:%s/metrics", proto, host, port)
	log.Printf("Performing health check against %s", targetURL)

	client := http.Client{Timeout: 10 * time.Second}
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
	log.Println("Health check successful.")
	os.Exit(0)
}

// --- Main Function (Mostly unchanged setup, registers new probeHandler) ---

func main() {
	configFile := flag.String("config.file", "config.yaml", "Path to configuration file.")
	healthcheck := flag.Bool("healthcheck", false, "Perform a health check against the configured listen address and exit.")
	flag.Parse()

	log.Printf("Reading configuration from %s", *configFile)
	appConfig, err := readConfig(*configFile)
	if err != nil {
		log.Fatalf("Fatal: Error reading configuration: %v", err)
	}

	if *healthcheck {
		performHealthCheck(appConfig.Listen)
		return
	}

	log.Printf("Configuration read successfully. %d valid targets loaded.", len(appConfig.TargetsMap))
	log.Printf("Default probe timeout: %d seconds", appConfig.DefaultTimeoutSeconds)

	metricDescs := newMetricDescriptions()

	// Register handlers
	http.HandleFunc("/probe", probeHandler(appConfig, metricDescs))
	http.Handle("/metrics", promhttp.Handler())                         // Exporter's own metrics
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { // Root handler
		_, _ = w.Write([]byte(`<html><head><title>Switch Exporter</title></head><body>
			<h1>Switch Exporter</h1>
			<p><a href="/probe">Probe Switches (requires 'target' parameter)</a></p>
			<p><a href="/metrics">Exporter Metrics</a></p>
			</body></html>`))
	})

	// Start HTTP server
	log.Printf("Starting Switch Exporter on %s", appConfig.Listen)
	server := &http.Server{Addr: appConfig.Listen}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("Shutting down exporter...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	} else {
		log.Println("HTTP server gracefully stopped.")
	}
}
