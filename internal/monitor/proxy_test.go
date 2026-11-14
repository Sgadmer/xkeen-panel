package monitor

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func closedAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func TestSelectiveProbeStatusIsScopedToCurrentRoute(t *testing.T) {
	w := newWatchdog(t, &models.Config{})
	dir := t.TempDir()
	initScript := filepath.Join(dir, "S05xkeen")
	if err := os.WriteFile(initScript, []byte("name_client=mihomo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	w.detector = xkeen.NewDetector(dir, "", initScript, "", "", "", "")
	for _, selective := range []bool{true, false} {
		w.SetMihomoProbe(func(context.Context, string) (models.RouteProbe, error) {
			return models.RouteProbe{Name: "Node", Protocol: "VLESS", Latency: 17, Checked: true, Selective: selective}, nil
		})
		w.check(false)
		s := w.GetStatus()
		if s.Selective != selective || !s.ProxyChecked || !s.Connected || s.Latency != 17 || s.CurrentServer != "Node" {
			t.Fatalf("status did not describe the measured route: %+v", s)
		}
	}
}

// The direct link works but nothing gets through the core: that is a dead
// exit, the one case failover exists for.
func TestCheckCountsDeadProxy(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer site.Close()

	w := newWatchdog(t, &models.Config{CheckURL: site.URL, MaxFails: 5})
	w.SetProbeAddr(closedAddr(t))

	w.check(true)

	st := w.GetStatus()
	if st.Connected || !st.Internet || !st.ProxyChecked {
		t.Errorf("status = connected %v, internet %v, proxy_checked %v; want false, true, true", st.Connected, st.Internet, st.ProxyChecked)
	}
	if w.failCount != 1 {
		t.Errorf("failCount = %d, want 1", w.failCount)
	}
}

// With the uplink itself down, switching nodes cannot help and must not count.
func TestCheckIgnoresDeadUplink(t *testing.T) {
	w := newWatchdog(t, &models.Config{CheckURL: "http://" + closedAddr(t), MaxFails: 1})
	w.SetProbeAddr(closedAddr(t))

	w.check(true)

	if st := w.GetStatus(); st.Connected || st.Internet {
		t.Errorf("connected %v, internet %v; want both false", st.Connected, st.Internet)
	}
	if w.failCount != 0 {
		t.Errorf("failCount = %d, want 0 — a dead uplink is not the node's fault", w.failCount)
	}
}

// Without a probe inbound the check is direct, and the status has to say so
// rather than pass a working uplink off as a working proxy.
func TestCheckWithoutProbeIsUnverified(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer site.Close()

	w := newWatchdog(t, &models.Config{CheckURL: site.URL, MaxFails: 5})
	w.check(true)

	if st := w.GetStatus(); !st.Connected || st.ProxyChecked {
		t.Errorf("connected %v, proxy_checked %v; want true, false", st.Connected, st.ProxyChecked)
	}
}
