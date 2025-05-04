package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

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
