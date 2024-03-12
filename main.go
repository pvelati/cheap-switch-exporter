package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Address  string `yaml:"address"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
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

func main() {

	// Read config.json
	config, err := readConfig("config.yaml")
	if err != nil {
		log.Fatal("Error reading configuration:", err)
	}

	// Check if required fields are provided in the configuration file
	if config.Address == "" || config.Username == "" || config.Password == "" {
		log.Fatal("Missing required fields in the configuration file.")
	}

	// Set the base URL
	baseURL := "http://" + config.Address + "/port.cgi?page=stats"

	// Set the URL parameters
	params := url.Values{}
	params.Set("page", "stats")

	// Set the form parameters
	formParams := url.Values{}
	username := config.Username
	password := config.Password
	formParams.Set("username", username)
	formParams.Set("password", password)
	formParams.Set("language", "EN")
	formParams.Set("Response", getMD5Hash(username+password))

	// Create a new HTTP client
	client := &http.Client{}

	// Create Prometheus metrics
	portState := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "port_state",
		Help: "State of the port",
	}, []string{"port"})
	portLinkStatus := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "port_link_status",
		Help: "Link status of the port",
	}, []string{"port"})
	portTxGoodPkt := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "port_tx_good_pkt",
		Help: "Number of good packets transmitted on the port",
	}, []string{"port"})
	portTxBadPkt := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "port_tx_bad_pkt",
		Help: "Number of bad packets transmitted on the port",
	}, []string{"port"})
	portRxGoodPkt := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "port_rx_good_pkt",
		Help: "Number of good packets received on the port",
	}, []string{"port"})
	portRxBadPkt := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "port_rx_bad_pkt",
		Help: "Number of bad packets received on the port",
	}, []string{"port"})

	// Expose our metrics with a custom registry
	r := prometheus.NewRegistry()
	handler := promhttp.HandlerFor(r, promhttp.HandlerOpts{})

	// Register Prometheus metrics
	r.MustRegister(portState)
	r.MustRegister(portLinkStatus)
	r.MustRegister(portTxGoodPkt)
	r.MustRegister(portTxBadPkt)
	r.MustRegister(portRxGoodPkt)
	r.MustRegister(portRxBadPkt)

	// Start the Prometheus exporter endpoint
	http.Handle("/metrics", handler)
	fmt.Println("Starting Prometheus exporter on :8080/metrics")
	go func() {
		log.Fatal(http.ListenAndServe(":8080", nil))
	}()

	// Start updating the values every second
	ticker := time.NewTicker(1 * time.Second)
	for range ticker.C {
		// Create a new GET request with the parameters
		req, err := http.NewRequest("GET", baseURL, strings.NewReader(formParams.Encode()))
		if err != nil {
			log.Println("Error creating request:", err)
			continue
		}

		// Set the cookie header
		cookieValue := getMD5Hash(username + password)
		cookie := &http.Cookie{Name: "admin", Value: cookieValue}
		req.AddCookie(cookie)

		// Set the Content-Type header
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// Set the request parameters
		req.URL.RawQuery = params.Encode()

		// Send the request
		resp, err := client.Do(req)
		if err != nil {
			log.Println("Error sending request:", err)
			continue
		}

		// Load the HTML document
		doc, err := goquery.NewDocumentFromReader(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Println("Error loading HTML document:", err)
			continue
		}

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

		// Update Prometheus metrics
		for _, port := range stats.Ports {
			portState.WithLabelValues(port.Name).Set(stateToFloat(port.State))
			portLinkStatus.WithLabelValues(port.Name).Set(linkStatusToFloat(port.LinkStatus))
			portTxGoodPkt.WithLabelValues(port.Name).Set(float64(port.TxGoodPkt))
			portTxBadPkt.WithLabelValues(port.Name).Set(float64(port.TxBadPkt))
			portRxGoodPkt.WithLabelValues(port.Name).Set(float64(port.RxGoodPkt))
			portRxBadPkt.WithLabelValues(port.Name).Set(float64(port.RxBadPkt))
		}
	}
}

// Helper function to convert port state to float
func stateToFloat(state string) float64 {
	if state == "Enable" {
		return 1
	}
	return 0
}

// Helper function to convert link status to float
func linkStatusToFloat(status string) float64 {
	if status == "Link Up" {
		return 1
	}
	return 0
}

// Helper function to calculate MD5 hash
func getMD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

// Helper function to read config file
func readConfig(filename string) (Config, error) {
	var config Config

	// Read the configuration file
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return config, err
	}

	// Unmarshal the YAML data into the Config struct
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return config, err
	}

	return config, nil
}
