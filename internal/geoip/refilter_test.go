package geoip

import (
	"os"
	"testing"
)

func domainEntry(kind uint64, name string) []byte {
	return append(varintField(1, kind), lenDelim(2, []byte(name))...)
}

func TestRefilterConvertsOnlySelectedTag(t *testing.T) {
	t.Run("domain boundaries", func(t *testing.T) {
		f, err := ReadRefilter(writeDat(t, geoEntry("PRIVATE", domainEntry(2, "ignore.test")), geoEntry("refilter", domainEntry(2, "blocked.test"), domainEntry(3, "exact.test"))), true)
		if err != nil || f.Count != 2 || f.Behavior != "domain" || string(f.Data) != "+.blocked.test\nexact.test\n" {
			t.Fatalf("%+v %v", f, err)
		}
	})
	t.Run("preserve classical types", func(t *testing.T) {
		f, err := ReadRefilter(writeDat(t, geoEntry("REFILTER", domainEntry(0, "fragment"), domainEntry(1, "^prefix"), domainEntry(2, "suffix.test"), domainEntry(3, "exact.test"))), true)
		if err != nil || f.Count != 4 || f.Behavior != "classical" || string(f.Data) != "DOMAIN-KEYWORD,fragment\nDOMAIN-REGEX,^prefix\nDOMAIN-SUFFIX,suffix.test\nDOMAIN,exact.test\n" {
			t.Fatalf("%+v %v", f, err)
		}
	})
	t.Run("both IP families", func(t *testing.T) {
		address := make([]byte, 16)
		address[0], address[1] = 0x20, 1
		f, err := ReadRefilter(writeDat(t, geoEntry("PRIVATE", cidr([]byte{10, 0, 0, 0}, 8)), geoEntry("REFILTER", cidr([]byte{192, 0, 2, 2}, 24), cidr(address, 64))), false)
		if err != nil || f.Count != 2 || string(f.Data) != "192.0.2.0/24\n2001::/64\n" {
			t.Fatalf("%+v %v", f, err)
		}
	})
	for _, name := range []string{"*.example", "bad\nexample", "example.com,DIRECT", "привет.рф"} {
		if _, err := ReadRefilter(writeDat(t, geoEntry("REFILTER", domainEntry(2, name))), true); err == nil {
			t.Errorf("accepted invalid file with %q", name)
		}
	}
	for _, entry := range [][]byte{geoEntry("PRIVATE", cidr([]byte{192, 0, 2, 0}, 24)), geoEntry("REFILTER", cidr([]byte{1}, 4)), geoEntry("REFILTER", cidr([]byte{192, 0, 2, 0}, 0)), append(geoEntry("REFILTER", cidr([]byte{192, 0, 2, 0}, 24)), varintField(3, 1)...)} {
		if _, err := ReadRefilter(writeDat(t, entry), false); err == nil {
			t.Error("accepted empty, reversed or invalid CIDR file")
		}
	}
	p := writeDat(t, geoEntry("REFILTER", domainEntry(2, "example.org")))
	b, _ := os.ReadFile(p)
	_ = os.WriteFile(p, b[:len(b)-1], 0600)
	if _, err := ReadRefilter(p, true); err == nil {
		t.Fatal("accepted truncated input")
	}
}
