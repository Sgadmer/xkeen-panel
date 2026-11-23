package cardcontroller

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"xkeen-panel/internal/trafficlog"
)

// Mihomo logs a sniffed connection by address; the journal names the site the
// core saw on the open connection, and asks the core only once for it.
func TestRecentJournalNamesTheSiteInsteadOfItsAddress(t *testing.T) {
	calls := 0
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"connections":[{"id":"a","metadata":{"sourceIP":"::ffff:192.0.2.7","destinationIP":"198.51.100.4","destinationPort":"443","sniffHost":"video.example.com"}}]}`))
	}))
	defer core.Close()
	r := &trafficRecorder{}
	p := profile{api: coreAPI{base: core.URL, client: core.Client()}}
	entry := trafficlog.Entry{Device: "192.0.2.7", Host: "198.51.100.4", Port: "443"}
	if got := r.siteName(p, entry); got != "video.example.com" {
		t.Fatalf("the site behind the address is named, got %q", got)
	}
	if got := r.siteName(p, entry); got != "video.example.com" || calls != 1 {
		t.Fatalf("a known address is answered from memory: %q after %d requests", got, calls)
	}
	entry.Host = "example.org"
	if got := r.siteName(p, entry); got != "" || calls != 1 {
		t.Fatalf("a name needs no lookup: %q after %d requests", got, calls)
	}
}
