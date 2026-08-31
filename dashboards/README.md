# Example dashboard and alerting rules

Starting points, not finished products. Both files are validated by
`dashboards_test.go`, which fails if they query a metric the exporter does not
publish, so they cannot silently drift out of date.

| File | What it is |
|------|------------|
| `cheap-switch-exporter.json` | Grafana dashboard |
| `cheap-switch-exporter.rules.yml` | Prometheus alerting rules |

## Importing the dashboard

In Grafana: **Dashboards -> New -> Import -> Upload JSON file**, then pick your
Prometheus data source when prompted.

Or provision it, which is what you want if more than one person relies on it:

```yaml
# /etc/grafana/provisioning/dashboards/cheap-switch-exporter.yaml
apiVersion: 1
providers:
  - name: cheap-switch-exporter
    type: file
    options:
      path: /var/lib/grafana/dashboards
```

and copy `cheap-switch-exporter.json` into that directory.

The dashboard has two variables. **Data source** selects the Prometheus
instance. **Switch** is the `instance` label, populated from
`label_values(exporter_up, instance)` — one exporter serves one switch, so this
is how you pick between them.

## Loading the alerting rules

```yaml
# prometheus.yml
rule_files:
  - /etc/prometheus/rules/cheap-switch-exporter.rules.yml
```

Check them before reloading:

```bash
promtool check rules cheap-switch-exporter.rules.yml
```

`SwitchUnreachable` is the one to keep. The port-level rules need tuning:
`SwitchPortLinkDown` fires for every unused port on a switch with spare
capacity, and a sensible bad-packet threshold depends entirely on the site.
`SwitchExporterDown` matches jobs named `*switch*`; adjust it to whatever your
scrape configuration calls this exporter.

## Things worth knowing before you build on these

**Counters are packets, not bytes.** These switches expose `TxGoodPkt` and
`RxGoodPkt` only, so the traffic panels are in packets per second and cannot be
converted to bits per second. There is no byte counter to scale.

**Gaps in the panels are meaningful.** The exporter publishes no sample for a
value it could not interpret, rather than a zero, because a fabricated zero on a
counter looks like a device reset. A gap means the firmware reported something
unfamiliar; `--log.level=debug` names the cell.

**PoE panels stay empty unless `poe` is enabled** in the exporter
configuration.

**The metric names may change in a future major version.** They currently carry
no namespace prefix and the counters are not named `*_total`, which is why the
exporter does not offer OpenMetrics. If that is fixed, this dashboard and these
rules change with it, and the tests will say so.
