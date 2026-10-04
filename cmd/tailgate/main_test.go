package main

import (
	"context"
	"testing"
)

func TestParseArgs(t *testing.T) {
	d, a, e := parseArgs([]string{"host", "list", "--data-dir", "/tmp/tailgate-test"})
	if e != nil || d != "/tmp/tailgate-test" || len(a) != 2 {
		t.Fatal(d, a, e)
	}
	if _, _, e = parseArgs([]string{"--data-dir"}); e == nil {
		t.Fatal("missing directory")
	}
}

func TestUnknownCommand(t *testing.T) {
	if e := execute(context.Background(), []string{"--data-dir", t.TempDir(), "version"}); e != nil {
		t.Fatal(e)
	}
	if _, a, e := parseArgs([]string{"--data-dir=/tmp/tailgate-cli", "token", "list"}); e != nil || len(a) != 2 {
		t.Fatal(a, e)
	}
}
