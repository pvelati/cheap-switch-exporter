package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"

	"cheap-switch-exporter/internal/collector"
	"cheap-switch-exporter/internal/switchclient"
)

// The dashboard and the alerting rules are only useful if they refer to metrics
// this exporter actually publishes. These tests fail if a metric is renamed or
// removed without the shipped examples being updated, which is the situation the
// eventual *_total rename will create.

const (
	dashboardFile = "dashboards/cheap-switch-exporter.json"
	rulesFile     = "dashboards/cheap-switch-exporter.rules.yml"
)

// exporterMetric matches the metric families this exporter owns. Anything else
// in an expression (rate, count, instance, port, up) is not ours to verify.
var exporterMetric = regexp.MustCompile(`\b(?:port|poe|exporter)_[a-z0-9_]+\b`)

// exposedMetrics collects every metric family name the collector can emit.
func exposedMetrics(t *testing.T) map[string]bool {
	t.Helper()

	c := collector.New(context.Background(), collector.Options{
		Client: staticClient{},
		PoE:    true,
	})
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("registering collector: %v", err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gathering: %v", err)
	}

	names := make(map[string]bool, len(families))
	for _, f := range families {
		names[f.GetName()] = true
	}
	if len(names) < 17 {
		t.Fatalf("only %d metric families collected, the fixture is not exercising everything", len(names))
	}
	return names
}

// staticClient reports one port and one PoE port so that every descriptor the
// collector owns shows up in the gathered output.
type staticClient struct{}

func (staticClient) PortStatistics(context.Context) ([]switchclient.Port, error) {
	yes, zero := true, uint64(0)
	return []switchclient.Port{{
		Name: "1", Enabled: &yes, LinkUp: &yes,
		TxGoodPkt: &zero, TxBadPkt: &zero, RxGoodPkt: &zero, RxBadPkt: &zero,
	}}, nil
}

func (staticClient) PoEPorts(context.Context) ([]switchclient.PoEPort, error) {
	yes, class, one := true, uint8(3), 1.0
	return []switchclient.PoEPort{{
		Name: "1", Enabled: &yes, PowerOn: &yes, Class: &class,
		Watts: &one, Voltage: &one, Current: &one,
	}}, nil
}

func (staticClient) PoESystem(context.Context) (switchclient.PoESystem, error) {
	return switchclient.PoESystem{ConsumptionWatts: 1}, nil
}

func TestDashboardReferencesOnlyRealMetrics(t *testing.T) {
	exposed := exposedMetrics(t)

	raw, err := os.ReadFile(dashboardFile)
	if err != nil {
		t.Fatalf("reading dashboard: %v", err)
	}
	var dashboard map[string]any
	if err := json.Unmarshal(raw, &dashboard); err != nil {
		t.Fatalf("dashboard is not valid JSON: %v", err)
	}

	exprs := collectExprs(dashboard)
	if len(exprs) < 10 {
		t.Fatalf("found only %d queries in the dashboard, expected more", len(exprs))
	}

	referenced := map[string]bool{}
	for _, expr := range exprs {
		for _, name := range exporterMetric.FindAllString(expr, -1) {
			referenced[name] = true
			if !exposed[name] {
				t.Errorf("dashboard queries %q, which the exporter does not publish\n  in: %s", name, expr)
			}
		}
	}
	t.Logf("dashboard references %d exporter metrics across %d queries", len(referenced), len(exprs))
}

func TestRulesReferenceOnlyRealMetrics(t *testing.T) {
	exposed := exposedMetrics(t)

	raw, err := os.ReadFile(rulesFile)
	if err != nil {
		t.Fatalf("reading rules: %v", err)
	}
	var rules struct {
		Groups []struct {
			Name  string `yaml:"name"`
			Rules []struct {
				Alert string `yaml:"alert"`
				Expr  string `yaml:"expr"`
				For   string `yaml:"for"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(raw, &rules); err != nil {
		t.Fatalf("rules file is not valid YAML: %v", err)
	}
	if len(rules.Groups) == 0 {
		t.Fatal("no rule groups found")
	}

	count := 0
	for _, g := range rules.Groups {
		for _, r := range g.Rules {
			count++
			if r.Alert == "" || r.Expr == "" {
				t.Errorf("rule in group %q is missing an alert name or expression", g.Name)
			}
			for _, name := range exporterMetric.FindAllString(r.Expr, -1) {
				if !exposed[name] {
					t.Errorf("alert %s queries %q, which the exporter does not publish", r.Alert, name)
				}
			}
		}
	}
	if count < 4 {
		t.Errorf("only %d alerting rules, expected the shipped set", count)
	}
}

// Every panel must be wired to the templated data source, otherwise the
// dashboard imports with panels pointing at whatever happens to be default.
func TestDashboardPanelsUseTemplatedDatasource(t *testing.T) {
	raw, err := os.ReadFile(dashboardFile)
	if err != nil {
		t.Fatalf("reading dashboard: %v", err)
	}
	var dashboard struct {
		Title      string `json:"title"`
		UID        string `json:"uid"`
		Templating struct {
			List []struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"list"`
		} `json:"templating"`
		Panels []struct {
			Title      string `json:"title"`
			Type       string `json:"type"`
			Datasource *struct {
				UID string `json:"uid"`
			} `json:"datasource"`
		} `json:"panels"`
	}
	if err := json.Unmarshal(raw, &dashboard); err != nil {
		t.Fatalf("unmarshalling dashboard: %v", err)
	}

	if dashboard.Title == "" || dashboard.UID == "" {
		t.Error("dashboard needs a title and a uid to be importable")
	}

	var vars []string
	for _, v := range dashboard.Templating.List {
		vars = append(vars, v.Name)
	}
	sort.Strings(vars)
	for _, want := range []string{"datasource", "instance"} {
		if !contains(vars, want) {
			t.Errorf("missing template variable %q, have %v", want, vars)
		}
	}

	for _, p := range dashboard.Panels {
		if p.Type == "row" {
			continue
		}
		if p.Datasource == nil || !strings.Contains(p.Datasource.UID, "${datasource}") {
			t.Errorf("panel %q does not use the templated data source", p.Title)
		}
	}
}

// collectExprs walks the decoded dashboard and returns every "expr" string.
func collectExprs(node any) []string {
	var out []string
	switch v := node.(type) {
	case map[string]any:
		for key, value := range v {
			if key == "expr" {
				if s, ok := value.(string); ok && s != "" {
					out = append(out, s)
				}
				continue
			}
			out = append(out, collectExprs(value)...)
		}
	case []any:
		for _, item := range v {
			out = append(out, collectExprs(item)...)
		}
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// Keep the example files inside the repository, not somewhere else on disk.
func TestDashboardFilesExist(t *testing.T) {
	for _, f := range []string{dashboardFile, rulesFile, filepath.Join("dashboards", "README.md")} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}
