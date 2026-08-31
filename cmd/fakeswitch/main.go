// Command fakeswitch serves an emulated switch web interface.
//
// It exists so the exporter can be exercised, demonstrated and load-tested
// without hardware:
//
//	go run ./cmd/fakeswitch -profile standard -listen 127.0.0.1:8081
//	CSE_ADDRESS=127.0.0.1:8081 CSE_USERNAME=admin CSE_PASSWORD=admin \
//	  go run . --web.listen-address 127.0.0.1:9101
//
// Counters advance with wall-clock time, so rate() over the fake produces a
// plausible graph in Prometheus or Grafana.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"cheap-switch-exporter/internal/fakeswitch"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "fakeswitch: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("fakeswitch", flag.ContinueOnError)
	fs.SetOutput(out)

	names := make([]string, 0, len(fakeswitch.Profiles()))
	for _, p := range fakeswitch.Profiles() {
		names = append(names, string(p))
	}

	listen := fs.String("listen", "127.0.0.1:8081", "Address to listen on.")
	profile := fs.String("profile", string(fakeswitch.ProfileStandard),
		"Firmware to emulate: "+strings.Join(names, ", ")+".")
	ports := fs.Int("ports", 8, "Number of switch ports to report.")
	username := fs.String("username", "admin", "Expected username.")
	password := fs.String("password", "admin", "Expected password.")
	seed := fs.Int64("seed", 1, "Seed for the generated traffic.")
	delay := fs.Duration("delay", 30*time.Second, "Response delay for the slow profile.")
	list := fs.Bool("list-profiles", false, "Print the available profiles and exit.")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *list {
		for _, p := range fakeswitch.Profiles() {
			poe := ""
			if p.SupportsPoE() {
				poe = "  (serves the PoE pages)"
			}
			fmt.Fprintf(out, "%s%s\n", p, poe)
		}
		return nil
	}
	if !isKnownProfile(*profile) {
		return fmt.Errorf("unknown profile %q, want one of: %s", *profile, strings.Join(names, ", "))
	}

	sw := fakeswitch.New(fakeswitch.Options{
		Profile:  fakeswitch.Profile(*profile),
		Ports:    *ports,
		Username: *username,
		Password: *password,
		Seed:     *seed,
		Delay:    *delay,
	})

	srv := &http.Server{
		Addr:              *listen,
		Handler:           sw,
		ReadHeaderTimeout: 5 * time.Second,
	}
	fmt.Fprintf(out, "fake switch %q with %d ports on http://%s\n", *profile, *ports, *listen)
	fmt.Fprintf(out, "point the exporter at it with:\n"+
		"  CSE_ADDRESS=%s CSE_USERNAME=%s CSE_PASSWORD=%s go run . --web.listen-address 127.0.0.1:9101\n",
		*listen, *username, *password)
	return srv.ListenAndServe()
}

func isKnownProfile(name string) bool {
	for _, p := range fakeswitch.Profiles() {
		if string(p) == name {
			return true
		}
	}
	return false
}
