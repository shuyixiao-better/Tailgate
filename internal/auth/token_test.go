package auth

import "testing"

func TestToken(t *testing.T) {
	a, e := Generate()
	if e != nil {
		t.Fatal(e)
	}
	b, _ := Generate()
	if len(a) < 40 || a == b {
		t.Fatal("entropy")
	}
	if !Match(a, Hash(a)) || Match(b, Hash(a)) || Match(a, "bad") {
		t.Fatal("match")
	}
}
