package main

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

type switchScrapeCollector struct {
	targetLabelValue string
	descs            *MetricDescriptions
	portStats        *PortStatistics
	stpStats         *STPPortStatistics
	probeDuration    float64
	probeSuccess     bool
}
