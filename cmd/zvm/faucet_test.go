package main

import (
	"net/http"
	"testing"
)

// The fleet benchmark's defect 3: the cooldown was keyed on the first
// X-Forwarded-For hop, which the client writes, so a new value in each request
// walked around it.
func TestClientKeyDoesNotBelieveTheCaller(t *testing.T) {
	req := func(remote, xff string) *http.Request {
		r, err := http.NewRequest(http.MethodPost, "/drip", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	proxies, err := parseTrustedProxies("10.0.0.0/8, 192.168.1.7")
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name    string
		remote  string
		xff     string
		trusted string
		want    string
	}{
		{"no proxies configured: the peer, whatever the header says",
			"203.0.113.9:5555", "1.2.3.4", "", "203.0.113.9"},
		{"an untrusted peer's header is ignored",
			"203.0.113.9:5555", "1.2.3.4", "10.0.0.0/8, 192.168.1.7", "203.0.113.9"},
		{"a trusted proxy's last hop is the client it saw",
			"10.1.2.3:5555", "1.2.3.4", "10.0.0.0/8, 192.168.1.7", "1.2.3.4"},
		{"a header the client pre-filled cannot shift the key: the last hop still wins",
			"10.1.2.3:5555", "9.9.9.9, 1.2.3.4", "10.0.0.0/8, 192.168.1.7", "1.2.3.4"},
		{"two of our own proxies in the chain",
			"10.1.2.3:5555", "1.2.3.4, 192.168.1.7", "10.0.0.0/8, 192.168.1.7", "1.2.3.4"},
		{"a trusted peer with no header at all",
			"10.1.2.3:5555", "", "10.0.0.0/8, 192.168.1.7", "10.1.2.3"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var trust = proxies
			if c.trusted == "" {
				trust = nil
			}
			if got := clientKey(req(c.remote, c.xff), trust); got != c.want {
				t.Fatalf("keyed on %q, want %q", got, c.want)
			}
		})
	}

	// And the one that matters: a client spoofing a different value each time
	// cannot get a different key.
	for _, spoof := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		if got := clientKey(req("203.0.113.9:5555", spoof), proxies); got != "203.0.113.9" {
			t.Fatalf("a spoofed header moved the key to %q", got)
		}
	}
}

func TestParseTrustedProxiesRefusesNonsense(t *testing.T) {
	if _, err := parseTrustedProxies("not-an-address"); err == nil {
		t.Fatal("accepted")
	}
	got, err := parseTrustedProxies("  ")
	if err != nil || len(got) != 0 {
		t.Fatalf("empty should be empty: %v %v", got, err)
	}
}
