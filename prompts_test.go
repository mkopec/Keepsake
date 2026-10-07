package main

import "testing"

func TestDisplayText(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"alice", 64, "alice"},
		{"alice\nSign in to bank.com", 64, "aliceSign in to bank.com"},
		{"evil\u202emoc.knab", 64, "evilmoc.knab"},
		{"  padded\t", 64, "padded"},
		{"ąęść", 4, "ąęść"},
		{"abcdefgh", 4, "abcd…"},
	}
	for _, c := range cases {
		if got := displayText(c.in, c.max); got != c.want {
			t.Errorf("displayText(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
		}
	}
}
