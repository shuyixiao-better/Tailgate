package sshpool

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestShellQuote(t *testing.T) {
	for _, tc := range []struct{ input, want string }{{"", "''"}, {"a b", "'a b'"}, {"a'b", "'a'\"'\"'b'"}, {"$(touch x);\n", "'$(touch x);\n'"}} {
		if got := ShellQuote(tc.input); got != tc.want {
			t.Errorf("ShellQuote(%q)=%q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestRewriteSudo(t *testing.T) {
	for _, tc := range []struct {
		command string
		enabled bool
		want    string
		inject  bool
	}{
		{"sudo id", true, "sudo -S -p '' id", true}, {"sudo id", false, "sudo id", false}, {"echo sudo id", true, "echo sudo id", false}, {" sudo id", true, " sudo id", false}, {"sudo", true, "sudo", false},
	} {
		got, inject := RewriteSudo(tc.command, tc.enabled)
		if got != tc.want || inject != tc.inject {
			t.Errorf("rewrite %q = %q,%v", tc.command, got, inject)
		}
	}
}

func TestOutputCombinedBudgetAndUTF8(t *testing.T) {
	out, errOut := newHeadTailBuffer(96), newHeadTailBuffer(96)
	input := "HEAD" + strings.Repeat("你好", 200) + "TAIL"
	_, _ = out.Write([]byte(input))
	_, _ = errOut.Write(bytes.Repeat([]byte{0xff}, 200))
	a, b, truncated := renderOutput(out, errOut, 96)
	if !truncated || !utf8.ValidString(a) || !utf8.ValidString(b) {
		t.Fatalf("invalid truncated UTF-8: %q %q", a, b)
	}
	if len(a)+len(b) > 96 {
		t.Fatalf("combined output %d exceeds cap", len(a)+len(b))
	}
	if !strings.HasPrefix(a, "HEAD") || !strings.HasSuffix(a, "TAIL") {
		t.Fatalf("lost head or tail: %q", a)
	}
	_, total := out.snapshot()
	if total != int64(len(input)) {
		t.Fatalf("wrong original bytes %d", total)
	}
}

func TestOutputUntruncated(t *testing.T) {
	out, errOut := newHeadTailBuffer(20), newHeadTailBuffer(20)
	for _, s := range []string{"abc", "def", "ghi"} {
		_, _ = out.Write([]byte(s))
	}
	_, _ = errOut.Write([]byte("bad"))
	a, b, truncated := renderOutput(out, errOut, 20)
	if a != "abcdefghi" || b != "bad" || truncated {
		t.Fatalf("unexpected %q %q %v", a, b, truncated)
	}
}

func TestRedactionAcrossPackets(t *testing.T) {
	var output bytes.Buffer
	w := &redactingWriter{target: &output, secret: []byte("password")}
	for _, data := range []string{"before pa", "ss", "word after pass", "word!"} {
		if _, err := w.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.flush(); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "before [REDACTED] after [REDACTED]!" {
		t.Fatal(got)
	}
	if w.total != int64(len("before password after password!")) {
		t.Fatal("original count lost")
	}
}

func TestHashedHostMatching(t *testing.T) {
	// The hashed representation is exercised in the integration key update test.
	if !matchesHost("[127.0.0.1]:2222", "[127.0.0.1]:2222") || matchesHost("other", "target") {
		t.Fatal("host comparison")
	}
}
