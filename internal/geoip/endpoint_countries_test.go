package geoip

import (
	"bufio"
	"bytes"
	"context"
	"net/netip"
	"reflect"
	"testing"
)

func TestEndpointCountriesUseEveryAddressIncludingIPv6(t *testing.T) {
	a, b := netip.MustParseAddr("194.0.0.1"), netip.MustParseAddr("2a00::2")
	c := netip.MustParseAddr("195.0.0.3")
	both := netip.MustParseAddr("196.0.0.4")
	unmatched := netip.MustParseAddr("197.0.0.5")
	asCIDR := func(ip netip.Addr) []byte { return cidr(ip.AsSlice(), uint64(ip.BitLen())) }
	ru := geoEntry("RU", asCIDR(a), asCIDR(b), asCIDR(both))
	nl := geoEntry("NL", asCIDR(c), asCIDR(both))
	inverse := append(geoEntry("SO", asCIDR(a)), varintField(3, 1)...)
	var dat []byte
	for _, entry := range [][]byte{ru, nl, inverse} {
		dat = append(dat, lenDelim(1, entry)...)
	}
	hosts := map[string][]netip.Addr{"both-ru": {a, b}, "mixed": {a, c}, "unlisted": {a, unmatched}, "ambiguous": {both}, "nl": {c}, "same-mapped": {a, netip.MustParseAddr("::ffff:194.0.0.1")}, "dns-failed": nil}
	want := map[string]string{"both-ru": "RU", "nl": "NL", "same-mapped": "RU"}
	got := lookupEndpoints(context.Background(), bufio.NewReader(bytes.NewReader(dat)), hosts)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	got = lookupEndpoints(context.Background(), bufio.NewReader(bytes.NewReader(append(dat, 10, 5, 42))), hosts)
	if len(got) != 0 {
		t.Fatal("truncated country database yielded a partial mapping")
	}
}

func TestEndpointCountriesFindNonExcludedCountry(t *testing.T) {
	path := writeDat(t, geoEntry("NL", cidr([]byte{5, 6, 7, 0}, 24)))
	got := EndpointCountries(context.Background(), path, []string{"5.6.7.11", "5.6.7.11", "192.168.1.1"})
	if len(got) != 1 || got["5.6.7.11"] != "NL" {
		t.Fatal(got)
	}
}
