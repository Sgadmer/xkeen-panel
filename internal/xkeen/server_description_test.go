package xkeen

import (
	"encoding/base64"
	"testing"
)

func TestSplitServerDescription(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("Для игр"))
	cases := []struct{ in, name, description string }{
		{"Германия", "Германия", ""},
		{"Германия ?serverDescription=" + encoded, "Германия", "Для игр"},
		{"NL-1?serverDescription=Fast%20line", "NL-1", "Fast line"},
		{"?serverDescription=" + encoded, "?serverDescription=" + encoded, ""},
	}
	for _, c := range cases {
		name, description := SplitServerDescription(c.in)
		if name != c.name || description != c.description {
			t.Errorf("SplitServerDescription(%q) = %q, %q; want %q, %q", c.in, name, description, c.name, c.description)
		}
	}
}

func TestSubscriptionCarriesServerDescriptions(t *testing.T) {
	link := "vless://00000000-0000-4000-8000-000000000000@a.example:443?security=tls#DE-1?serverDescription=" + base64.StdEncoding.EncodeToString([]byte("Обход"))
	servers, _, err := ParseSubscriptionDetailed(link)
	if err != nil || len(servers) != 1 || servers[0].Name != "DE-1" || servers[0].Description != "Обход" {
		t.Fatalf("link: %+v, %v", servers, err)
	}
	profile := `{"remarks":"NL-2","meta":{"serverDescription":"Стабильный"},"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"b.example","port":443,"users":[{"id":"00000000-0000-4000-8000-000000000000","encryption":"none"}]}]},"streamSettings":{"security":"tls"}}]}`
	servers, _, err = ParseSubscriptionDetailed(profile)
	if err != nil || len(servers) != 1 || servers[0].Description != "Стабильный" {
		t.Fatalf("json: %+v, %v", servers, err)
	}
}
