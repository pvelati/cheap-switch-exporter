# Directives for coding agents

This file applies to any AI coding agent working in this repository. It records
the invariants of the project and the traps that have already caught someone, so
they do not have to be rediscovered.

Read `README.md` for what the exporter does. This file is about how to change it.

## Before you finish

```bash
make check
```

That is the contract: formatting, `go vet`, both binaries built, and the whole
test suite under the race detector. It takes about ten seconds and needs no
hardware. Do not report work as complete without it passing.

Use `make vuln` when touching dependencies and `make acceptance` when touching
the collector, the parsers or the HTTP layer.

`make lint` is expected to report zero issues. It needs a `golangci-lint` built
with a Go at least as new as the `go` directive in `go.mod`; an older one
mis-typechecks the sources and reports nonsense. The pinned version is in
`.github/workflows/ci.yml`.

## Repository map

| Path | Responsibility |
|------|----------------|
| `main.go` | Flags, logging, HTTP server, process lifecycle |
| `internal/config` | Schema, validation, secrets, redaction |
| `internal/switchclient` | Device transport and response interpretation, both firmware families |
| `internal/collector` | `prometheus.Collector`, nothing else |
| `internal/fakeswitch` | Device emulator shared by tests and `cmd/fakeswitch` |
| `cmd/fakeswitch` | Standalone emulator for manual testing and demos |
| `acceptance_test.go` | Black-box suite: real exporter against every fake firmware |

`switchclient` fully interprets the device and returns typed values; `collector`
only maps those to metrics. Keep that split. Neither package should learn about
the other's concerns.

## Invariants

**Never publish a value the device did not report.** Optional fields are
pointers; `nil` means the collector emits no sample. A fabricated `0` on a
counter looks like a device reset and shows up as a spike in `rate()`. This is
why `parseUint` returns `*uint64`.

**`Describe` must announce every descriptor `Collect` can emit.** A pedantic
registry test enforces this. An earlier version omitted all seven PoE
descriptors and nothing noticed.

**Do not use `promauto`, and do not register on the default registry.** The
collector owns its metrics and the caller owns the registry. A constructor that
mutates global state cannot be instantiated twice, which makes it untestable.

**Do not enable OpenMetrics.** `EnableOpenMetrics` is `false` on purpose, with
the reason in a comment next to it. OpenMetrics requires counter series to be
named `*_total`; the historical names here are not, so the encoder downgrades
every packet counter to type `unknown`, and Prometheus prefers OpenMetrics when
it is offered. Renaming the counters is the real fix and needs a major version.

**The exporter's own metrics are emitted unconditionally.** `exporter_up`,
`exporter_last_scrape_duration_seconds`, `exporter_scrape_errors_total` and
`exporter_build_info` must appear even when the device is unreachable. A series
that disappears exactly when things break cannot be alerted on.

**Two firmware families share one package.** `switchclient.Client` scrapes HTML
and `switchclient.JSONClient` reads `/port_statistics.json`. Both satisfy
`collector.SwitchClient`, so the collector does not know which is in use. Shared
helpers (`parseUint`, `parseEnabled`, `normalizePortName`, `md5Hex`) are reused
deliberately; keep new device support inside this seam rather than teaching the
collector about firmwares.

Their credential schemes differ and must not be unified: the HTML family sends
one `md5(username+password)` token, the JSON family hashes the two separately as
`loginusr` and `loginpwd`.

**Device quirks are load-bearing.** Each of these is required by a specific
firmware and must not be tidied away:

- the credential form is sent as the body of a `GET` request
- the `Referer` header, without which KeepLink returns an empty page
- the `admin` cookie carrying `md5(username+password)`, lowercase hex
- `0-` prefixed cells (KeepLink), thousands separators, unit suffixes, `Port N`
  names, non-breaking spaces
- lazy login: `POST /login.cgi` only after an empty answer, then one retry
  (issues #19 and #8)

**Never log credentials.** `Config.String()` redacts secrets and the auth token
is password-equivalent. Do not add a debug print of a request or a config struct.

## Backward compatibility

Preserve unless explicitly asked otherwise:

- **Metric names and label values.** They are the public contract.
- **Config keys**, including `poe: 1` and `poe: 0`.
- **The `-c` flag.** The container image invokes the binary with it. Adding flag
  parsing without `-c` once turned a silently ignored argument into a crash loop.
- **The minimum Go version.** `go get -u` silently raises the `go` directive in
  `go.mod`. If a dependency forces a bump, say so explicitly and update the
  Dockerfile base image and the README prerequisite in the same change.

There are three direct dependencies. Do not add more without a reason worth
stating.

## Testing conventions

**Adding a device support fixture:** drop the page in
`internal/switchclient/testdata/` and add one entry to the `fixtures` table in
`parse_test.go`. Do not write a bespoke test function. The full contributor
workflow is in the README under "Adding a new device".

**Use `testClient()`, not `http.DefaultClient`.** Sharing the default client
pools connections across tests, and `freeAddr` can reissue a port a previous test
used, which produced intermittent multi-second stalls.

**`t.Cleanup` is LIFO.** With `httptest`, a cleanup that unblocks a handler must
be registered *after* the server, otherwise `srv.Close()` waits on a handler that
nothing will release. This deadlocked the suite for ten minutes once.

**Assert on deterministic signals, not the clock.** Wall-clock thresholds near
the noise floor produce flaky tests. Prefer an assertion that only a real
regression can trigger.

**`internal/fakeswitch` has its own tests.** A test double that quietly stops
emulating a firmware would make the acceptance suite pass for the wrong reason.
If you change a profile, update its self-test.

## Git

- **Do not commit unless asked.**
- **`.gitignore` patterns must be root-anchored.** An unanchored `fakeswitch`
  line matched both `cmd/fakeswitch/` and `internal/fakeswitch/`, and committing
  would have silently dropped two source packages. Use `/fakeswitch`.
- Do not leave build artefacts or a real `config.yaml` in the tree.

## Settled decisions

These were considered and rejected. Do not reopen them without new information.

| Not doing | Why |
|-----------|-----|
| Retries inside a scrape | Prometheus retries by scraping again; retrying burns the scrape budget and hammers a fragile device |
| Readiness tied to device state | Kubernetes would cycle pods whenever a switch reboots |
| Multi-target `/probe?target=` | A different product shape, not a refactor |
| HTTPS to the device | No evidence any of these firmwares serve TLS |
| `prometheus/exporter-toolkit` | Roughly fifteen transitive dependencies for a project with three; TLS and basic auth are already covered by the `web` config section |
| Renaming metrics now | Breaks every existing dashboard; belongs in a major version |

## When you are unsure

State what you verified and what you did not. Do not present an assumption as a
fact. If a claim about behaviour matters, prove it with a test or a command and
show the output.
