# 🔌 Cheap Switch Exporter

Prometheus Exporter for low-cost network switches without SNMP support

## 📖 Overview

This Prometheus exporter retrieves port statistics from switches that lack SNMP functionality, enabling monitoring through a web-based interface.

## 🎯 Purpose

Many budget-friendly network switches do not support standard SNMP monitoring. This exporter provides a workaround by scraping port statistics directly from the switch's web interface.

## 🖥️ Supported Devices

| Manufacturer | Model          | Firmware | Status     | Contributor  |
|--------------|----------------|----------|------------|--------------|
| Ampcom       | WAMJHJ-8125MNG |          | ✅ Verified | @askainet    |
| Horaco       | ZX-SWTGW215AS  |          | ✅ Verified | @askainet    |
| Horaco       | ZX-SWTGW218AS  |          | ✅ Verified | @pvelati     |
| Lianguo      | ZX-SWTGW215AS  | V1.9.1   | ✅ Verified | @madworx     |
| Sodola       | SL-SWTG124AS   |          | ✅ Verified | @dennyreiter |

## 🚀 Installation

### Prerequisites

- Go 1.23+
- Docker (optional)

### Direct Installation

1. Clone the repository
2. Download dependencies
```bash
go mod download
```

3. Copy configuration template
```bash
cp config.yaml.example config.yaml
```

4. Edit `config.yaml` with your switch details and parameters
5. Run the exporter
```bash
go run main.go
```

### Docker Deployment

```bash
# Build Docker image
docker build -t cheap-switch-exporter .

# Run container
docker run -v "./config.yaml:/config.yaml" -p 8080:8080 cheap-switch-exporter
```

## 📝 Configuration

Create a `config.yaml` with the following structure:

```yaml
address: "192.168.1.1"           # IP or hostname of the switch
username: "admin"                # Web interface username
password: "password"             # Web interface password
poll_rate_seconds: 10            # Metrics polling interval
timeout_seconds: 5               # Request timeout
```

## 📊 Exposed Metrics

- `port_state`: Port enabled/disabled status
- `port_link_status`: Port link up/down status
- `port_tx_good_pkt`: Transmitted good packets
- `port_tx_bad_pkt`: Transmitted bad packets
- `port_rx_good_pkt`: Received good packets
- `port_rx_bad_pkt`: Received bad packets

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## 🚨 Limitations

- Requires web interface access to the switch
- Polling-based metrics collection
- Authentication via web interface credentials
- No TLS

## 📄 License

MIT License, see [LICENSE](LICENSE) file.

## 🐛 Issues

Report issues on the GitHub repository's issue tracker.
