package keenetic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestWANReadsActiveDefaultUplinksOnly(t *testing.T) {
	const inventory = `{
		"wired":{"id":"Ethernet0/Vlan2","defaultgw":true,"global":true,"connected":"yes"},
		"mobile":{"id":"Cellular0","defaultgw":true,"global":true},
		"invalid":{"id":"Unknown0","defaultgw":true,"global":true},
		"old":{"defaultgw":true,"global":true,"connected":"no"},
		"Home":{"global":false}, "Wireguard0":{"global":true,"defaultgw":false}
	}`
	stats := map[string]string{"Ethernet0/Vlan2": `{"rxbytes":9007199254740993,"txbytes":16}`, "Cellular0": `{"rxbytes":0,"txbytes":0}`, "Unknown0": `{"status":"error"}`}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("X-Ndma-Tkn") != "test-token" {
			t.Errorf("unexpected method or missing local RCI token")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/rci/show/interface":
			_, _ = w.Write([]byte(inventory))
		case "/rci/show/interface/stat":
			name := r.URL.Query().Get("name")
			payload, ok := stats[name]
			if !ok {
				t.Errorf("queried a non-WAN interface %q", name)
			}
			_, _ = w.Write([]byte(payload))
		default:
			t.Errorf("unexpected RCI endpoint: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	got := NewClient(server.URL, "test-token").WANCounters(context.Background())
	want := map[string]TrafficCounters{"Ethernet0/Vlan2": {Received: 9007199254740993, Sent: 16}, "Cellular0": {}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("WAN counters = %v; want %v", got, want)
	}
}
