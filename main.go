package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

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

	http.HandleFunc("/probe", probeHandler(appConfig, metricDescs))
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/targets", targetsHandler(appConfig))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><head><title>Switch Exporter</title></head><body>
			<h1>Switch Exporter</h1>
			<p><a href="/probe">Probe Switches (requires 'target' parameter)</a></p>
			<p><a href="/metrics">Exporter Metrics</a></p>
			</body></html>`))
	})

	log.Printf("Starting Switch Exporter on %s", appConfig.Listen)
	server := &http.Server{Addr: appConfig.Listen}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

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

		h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{
			ErrorLog:      log.New(os.Stderr, "", log.LstdFlags),
			ErrorHandling: promhttp.ContinueOnError, // Or PanicOnError based on preference
		})
		h.ServeHTTP(w, r)
		log.Printf("Probe for target %s completed in %.2f seconds (Success: %t)", target, duration, success)
	}
}

func targetsHandler(appConfig AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targetGroups := make([]HttpSdTargetGroup, 0, len(appConfig.TargetsMap))

		for address, switchCfg := range appConfig.TargetsMap {
			labels := map[string]string{
				"__meta_switch_address": address,
				"switch_name":           switchCfg.Name,
				"job":                   "cheap-switch-exporter",
			}

			tg := HttpSdTargetGroup{
				Targets: []string{address},
				Labels:  labels,
			}
			targetGroups = append(targetGroups, tg)
		}

		jsonData, err := json.MarshalIndent(targetGroups, "", "  ")
		if err != nil {
			log.Printf("Error marshaling targets for HTTP SD: %v", err)
			http.Error(w, "Error generating target list", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(jsonData)
		if err != nil {
			log.Printf("Error writing HTTP SD response: %v", err)
		}
	}
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
