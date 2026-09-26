package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"strings"
	"testing"

	"cheap-switch-exporter/internal/fakeswitch"
)

func TestListProfiles(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"-list-profiles"}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, p := range fakeswitch.Profiles() {
		if !strings.Contains(out.String(), string(p)) {
			t.Errorf("profile %q is not listed", p)
		}
	}
	// The listing should say which profile serves the PoE pages.
	if !strings.Contains(out.String(), "PoE pages") {
		t.Errorf("the PoE profile is not marked:\n%s", out.String())
	}
}

func TestRejectsUnknownProfile(t *testing.T) {
	err := run([]string{"-profile", "nosuchdevice"}, io.Discard)
	if err == nil {
		t.Fatal("want an error for an unknown profile")
	}
	if !strings.Contains(err.Error(), "nosuchdevice") {
		t.Errorf("err = %v, want it to name the bad profile", err)
	}
	// The message should list the valid choices.
	if !strings.Contains(err.Error(), string(fakeswitch.ProfileStandard)) {
		t.Errorf("err = %v, want it to list the valid profiles", err)
	}
}

func TestRejectsUnknownFlag(t *testing.T) {
	if err := run([]string{"-nope"}, io.Discard); err == nil {
		t.Fatal("want an error for an unknown flag")
	}
}

func TestHelpIsNotAnError(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"-h"}, &out)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("err = %v, want flag.ErrHelp", err)
	}
	if !strings.Contains(out.String(), "-profile") {
		t.Errorf("help does not document the flags:\n%s", out.String())
	}
}

func TestIsKnownProfile(t *testing.T) {
	for _, p := range fakeswitch.Profiles() {
		if !isKnownProfile(string(p)) {
			t.Errorf("isKnownProfile(%q) = false", p)
		}
	}
	for _, name := range []string{"", "STANDARD", "unknown"} {
		if isKnownProfile(name) {
			t.Errorf("isKnownProfile(%q) = true, want false", name)
		}
	}
}
