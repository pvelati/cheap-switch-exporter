# cheap-switch-exporter
Prometheus Exporter for cheap switch boxes without SNMP  

## What
This prom-exporter is fetching port statistics from *http://<switch_address>/port.cgi?page=stats* and exposing them as metrics.  

## Why
There is no SNMP in the switch, there is no way to have better monitoring than navigating the integrated webui.  

## How
Copy config.yaml.example to config.yaml.  
Edit config.yaml with switch address and credentials.  

### Direct
```bash
go mod download
go run main.go
```

### Container
```bash
docker build -t cheap-switch-exporter .
docker run -v "./config.yaml:/config.yaml" -p 8080:8080 cheap-switch-exporter
```

&nbsp;

**Tested on**:
* Horaco ZX-SWTGW218AS

