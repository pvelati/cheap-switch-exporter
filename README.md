# Cheap Switch Exporter

Prometheus Exporter for low-cost network switches without SNMP support

## Overview

This Prometheus exporter retrieves port statistics from switches that lack SNMP functionality, by scraping the device's web interface.

## Purpose

Many budget-friendly network switches do not support standard SNMP monitoring. This exporter provides a workaround by scraping port statistics directly from the switch's web interface.

## Supported Devices

| Manufacturer | Model | Status | Contributor |
|--------------|-------|--------|-------------|
| Ampcom | WAMJHJ-8125MNG | Verified | @askainet |
| Horaco | ZX-SWTGW215AS | Verified | @askainet |
| Horaco | ZX-SWTGW218AS | Verified | @pvelati |
| Horaco | HC-SWTGW218AS | Verified | @arthurbarton |
| Horaco | HC-SWTGW124AS | Verified | @arthurbarton |
| KeepLink | KP-9000-9XHPML-X | Verified | @jfallot and @adamchabin |
| Sodola | SL-SWTG124AS | Verified | @dennyreiter |

## Installation

### Prerequisites

- Go 1.25+
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
chmod 600 config.yaml   # the file holds the switch password in clear text
```

4. Edit `config.yaml` with your switch details and parameters
5. Run the exporter
```bash
go run . -c config.yaml
```

### Docker Deployment

```bash
# Build Docker image
docker build -t cheap-switch-exporter .

# Run container (the image looks for /etc/cheap-switch-exporter/config.yaml)
docker run --rm \
  -v "$PWD/config.yaml:/etc/cheap-switch-exporter/config.yaml:ro" \
  -p 8080:8080 \
  cheap-switch-exporter
```

Multi-architecture builds (for example a Raspberry Pi) work out of the box:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg VERSION="$(git describe --tags --always --dirty)" \
  -t cheap-switch-exporter .
```

## Command line flags

| Flag | Default | Description |
|------|---------|-------------|
| `-c`, `--config` | `config.yaml` | Path to the configuration file |
| `--web.listen-address` | `:8080` | Address to listen on |
| `--web.telemetry-path` | `/metrics` | Path under which metrics are exposed |
| `--log.level` | `info` | `debug`, `info`, `warn` or `error` |
| `--log.format` | `text` | `text` or `json` |
| `--version` | | Print the version and exit |

Use `--log.level=debug` to see the values the exporter could not interpret; that is the fastest way to diagnose an unsupported firmware.

## Endpoints

| Path | Description |
|------|-------------|
| `/metrics` | Prometheus metrics. Polls the switch. |
| `/healthz` | Liveness probe. Does **not** touch the switch. |
| `/` | Landing page |

## Configuration

Create a `config.yaml` with the following structure (see `config.yaml.example`):

```yaml
address: "192.168.1.1"           # IP or hostname of the switch, no scheme
username: "admin"                # Web interface username
password: "password"             # Web interface password
poll_rate_seconds: 10            # Minimum delay between two polls of the switch
timeout_seconds: 5               # Per-request timeout
poe: false                       # Scrape the PoE pages (1/0 also accepted)
```

Unknown keys are rejected, so a misspelled option fails at startup instead of being ignored.

### Credentials from the environment

Any of these override the file, so secrets never have to be written to disk:

| Variable | Overrides |
|----------|-----------|
| `CSE_ADDRESS` | `address` |
| `CSE_USERNAME` | `username` |
| `CSE_PASSWORD` | `password` |
| `CSE_WEB_AUTH_USERNAME` | `web.auth_username` |
| `CSE_WEB_AUTH_PASSWORD` | `web.auth_password` |

If all mandatory values come from the environment, the configuration file may be absent entirely.

### Securing the metrics endpoint

Both sections are optional and disabled by default:

```yaml
web:
  tls_cert_file: "/etc/cheap-switch-exporter/tls.crt"
  tls_key_file: "/etc/cheap-switch-exporter/tls.key"
  auth_username: "prometheus"
  auth_password: "change-me"
```

TLS is served with a minimum version of TLS 1.2. `/healthz` is intentionally left unauthenticated so container health checks keep working. When the endpoint is bound to a non-loopback address without authentication, the exporter logs a warning at startup.

### Polling behaviour

`poll_rate_seconds` is the minimum delay between two polls of the switch. Scrapes arriving inside that window are answered from the previous result, including failures. That keeps a redundant pair of Prometheus servers, or a short scrape interval, from overwhelming a device whose web interface serves one session at a time. Set it to `0` to poll on every scrape.

### Session handling

These web interfaces are session based. Some firmwares (Horaco HC-SWTGW218AS, Binardat) serve the login page with HTTP 200 once no session exists, which used to make the exporter return values only while a browser happened to be logged in.

The exporter now authenticates lazily: it requests the statistics page, and only if the answer contains no data does it `POST /login.cgi` and retry once. On firmwares that need no handshake this costs nothing, and a session cookie issued by the device is stored and replayed. Persistent failure means the credentials are wrong or the page layout is unsupported, and shows up as `exporter_up 0` with the reason in the log.

## Exposed Metrics

### Port metrics

- `port_state`: Port enabled/disabled status (1=Enable, 0=Disable)
- `port_link_status`: Port link up/down status (1=Link Up, 0=Link Down)
- `port_tx_good_pkt`: Transmitted good packets
- `port_tx_bad_pkt`: Transmitted bad packets
- `port_rx_good_pkt`: Received good packets
- `port_rx_bad_pkt`: Received bad packets

The `port` label carries the bare port identifier (`1`, `2`, …) on both the port and the PoE metrics, so the two can be joined in PromQL.

A value the exporter cannot interpret produces no sample at all, rather than a zero. On a counter a fake zero would look like a device reset and would show up as a spike in `rate()`.

### PoE metrics (when enabled in config)

- `poe_port_power_on`: PoE port power on/off (1=On, 0=Off)
- `poe_port_state`: State of the PoE port (1=Enable, 0=Disable)
- `poe_port_type`: PoE power class, 1-8, 0 when no powered device is attached
- `poe_port_voltage`: PoE port voltage in volts
- `poe_port_watts`: PoE port power consumption in watts
- `poe_port_current_ma`: PoE port current in mA
- `poe_system_consumption_watts`: Total PoE consumption in watts

### Exporter metrics

- `exporter_up`: 1 when the last poll of the switch succeeded, 0 otherwise
- `exporter_last_scrape_duration_seconds`: Duration of the last poll
- `exporter_scrape_errors_total`: Failed requests to the switch
- `exporter_build_info`: Version and Go version of the running binary

Plus the standard `go_*`, `process_*` and `promhttp_*` metrics.

`exporter_up` is the series to alert on. It is always present, including while the switch is unreachable:

```promql
exporter_up == 0
```

## Development

Run this after every change:

```bash
make check
```

It checks formatting, runs `go vet`, builds both binaries and runs the whole test
suite under the race detector. It takes a few seconds and needs no hardware.

| Target | What it does |
|--------|--------------|
| `make check` | **The one to run after every change** |
| `make test` / `make race` | Tests, with or without the race detector |
| `make acceptance` | Only the black-box suite, verbose, one subtest per emulated firmware |
| `make cover` | Coverage summary (`make cover-html` for the browser view) |
| `make tidy` | Verify `go.mod` and `go.sum` are tidy |
| `make lint` | `golangci-lint`, if installed |
| `make vuln` | Scan dependencies with `govulncheck` |
| `make fake` | Run a fake switch on its own |
| `make demo` | Fake switch plus exporter, for poking at by hand |

### The fake switch

`cmd/fakeswitch` emulates the supported web interfaces, including their quirks
and their failure modes, so the exporter can be exercised without a device.
Counters advance with wall-clock time, so `rate()` over a fake produces a
plausible graph.

```bash
make demo                      # fake switch + exporter, metrics on :9101
make demo PROFILE=poe          # with the PoE pages
make fake PROFILE=session      # just the device, on :8081
go run ./cmd/fakeswitch -list-profiles
```

| Profile | Emulates |
|---------|----------|
| `standard` | The common interface: plain statistics table, no handshake |
| `quirks` | `Port N` names, grouped numbers, dashes, non-breaking spaces, a decoy table |
| `keeplink` | `0-` prefixed cells, empty response without a `Referer` |
| `session` | Data only after `POST /login.cgi` (issue #19) |
| `binardat` | Device-issued session cookie, synthetic one rejected (issue #8) |
| `poe` | Serves the PoE pages as well |
| `garbage` | No statistics table, i.e. an unsupported firmware |
| `unauthorized` | HTTP 401 |
| `slow` | Never answers in time |
| `flaky` | Drops the session every other request |

### Test layers

- **Unit** — parsers against HTML fixtures of the known firmware quirks
  (`internal/switchclient/testdata`), configuration loading and validation.
- **Collector** — `prometheus/testutil` golden output, plus a *pedantic* registry
  that fails if `Describe` and `Collect` ever disagree.
- **Simulator self-tests** — `internal/fakeswitch`, so a broken test double
  cannot make the acceptance suite pass for the wrong reason.
- **Acceptance** — `acceptance_test.go` starts the real exporter against every
  emulated firmware and asserts on the exposition output, the way Prometheus
  sees it.

When adding a device, a fixture of its statistics page is the most useful
contribution; a matching `fakeswitch` profile is even better.

## Adding a new device

If you own a switch that is not in the table above, these are the steps. You need
no Go experience for step 1, and step 2 alone is already a useful contribution.

### 1. Try it against your switch

```bash
cp config.yaml.example config.yaml
chmod 600 config.yaml
$EDITOR config.yaml               # address, username, password
go run . -c config.yaml --log.level=debug
```

In another terminal:

```bash
curl -s localhost:8080/metrics | grep -E '^(exporter_up|port_)'
```

Read `exporter_up` first:

| Result | Meaning |
|--------|---------|
| `exporter_up 1` with one `port_state` per physical port | It works. Open an issue with the model name and it goes in the table. |
| `exporter_up 1` but ports are missing, or values look wrong | The page layout is close but not identical. Go to step 2. |
| `exporter_up 0` | Look at the log line: wrong credentials, unreachable, or an unsupported layout. Go to step 2. |

`--log.level=debug` names every cell the exporter could not interpret, for example
an unfamiliar spelling in the State or Link Status column. That is usually enough
to identify what differs.

### 2. Capture the statistics page

Save exactly what your device returns. The request has to look like the
exporter's, because several firmwares only answer with the right cookie and
`Referer`:

```bash
ADDR=192.168.1.1
USER=admin
PASS=admin

# md5sum on Linux, md5 -q on macOS
TOKEN=$(printf '%s' "$USER$PASS" | { md5sum 2>/dev/null || md5 -q; } | cut -d' ' -f1)

curl -sS -X GET "http://$ADDR/port.cgi?page=stats" \
  --cookie "admin=$TOKEN" \
  --referer "http://$ADDR/menu.cgi" \
  --data "username=$USER&password=$PASS&language=EN&Response=$TOKEN" \
  -o port_stats_mymodel.html
```

If the result is a login page, your firmware needs a session first (see
[Session handling](#session-handling)); capture it again after:

```bash
curl -sS -X POST "http://$ADDR/login.cgi" -c /tmp/cookies.txt \
  --data "username=$USER&password=$PASS&language=EN&Response=$TOKEN"
```

and add `-b /tmp/cookies.txt` to the first command.

For a PoE switch, capture `/pse_port.cgi` and `/pse_system.cgi` the same way.

> **Scrub the file before sharing it.** These pages can contain MAC addresses,
> serial numbers, hostnames and VLAN names. Replace anything identifying; the
> parser only cares about the table structure.

Attaching that HTML to an issue is already the most useful thing you can
contribute, even if you stop here.

### 3. Add it to the test suite

Drop the file in `internal/switchclient/testdata/` and add one entry to the
`fixtures` table in `internal/switchclient/parse_test.go`:

```go
{
    device:    "Vendor MODEL-1234",
    file:      "port_stats_mymodel.html",
    wantPorts: 8,
    wantFirst: Port{
        Name: "1", Enabled: ptr(true), LinkUp: ptr(true),
        TxGoodPkt: ptr(uint64(1234567)), TxBadPkt: ptr(uint64(0)),
        RxGoodPkt: ptr(uint64(7654321)), RxBadPkt: ptr(uint64(3)),
    },
},
```

Fill `wantFirst` with the values your device actually shows in its first row. A
`nil` field asserts that the exporter publishes **no** sample for it, which is
the correct expectation for a cell containing `-`.

```bash
make check
```

If the test fails, the parser needs to learn your firmware's quirk. Those live in
`internal/switchclient/parse.go`, next to the existing ones (the KeepLink `0-`
prefix, thousands separators, unit suffixes, `Port N` names). Keep the change
additive so the other devices keep passing.

### 4. Optional: add a fake switch profile

A profile lets everyone exercise your firmware without owning it, including its
failure modes. Add a `Profile` constant and its behaviour in
`internal/fakeswitch/fakeswitch.go`, then a row in the table in
`acceptance_test.go`. Try it with:

```bash
make demo PROFILE=myprofile
```

### 5. Open the pull request

Include the model, the firmware version if the web UI shows one, and whether PoE
was tested. Run `make check` first.

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

Run `make check` before opening a pull request.

## AI-assisted development

Parts of this project, including the package layout, the test suite and the
device simulator, were written with the help of AI coding tools. Everything is
reviewed by a human before merging and has to pass `make check`, which builds
both binaries and runs the whole suite under the race detector.

The same expectation applies to contributions: AI assistance is welcome, working
and reviewed code is required.

If you point an agent at this repository, [`AGENTS.md`](AGENTS.md) records the
invariants it needs to respect: which device quirks are load-bearing, why
OpenMetrics is disabled, what must not be renamed, and which decisions have
already been settled.

## Limitations

- Requires web interface access to the switch
- Polling-based metrics collection
- Authentication against the switch uses whatever the device implements: an MD5 token over plain HTTP. Treat the management network accordingly.
- One switch per exporter instance

## License

MIT License, see [LICENSE](LICENSE) file.

## Issues

Report issues on the GitHub repository's issue tracker.
