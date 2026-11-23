package xkeen

import (
	"encoding/json"
	"strings"
	"testing"

	"xkeen-panel/internal/models"
)

// A provider's mode joins a pool as a loopback link to its own worker, and
// the pool worker accepts that config like any other.
func TestPoolTakesAProviderModeThroughItsWorker(t *testing.T) {
	plain := models.Server{RawURI: "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:10001?type=tcp"}
	mode := models.Server{Protocol: "xray-profile", RawProfile: json.RawMessage(`{"outbounds":[{"protocol":"vless","tag":"node",
		"settings":{"vnext":[{"address":"vpn.example.com","port":443,"users":[{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","encryption":"none"}]}]}}]}`)}
	modeKey, err := newServiceWorkerKey(20001)
	if err != nil {
		t.Fatal(err)
	}
	var asked []string
	pool, err := MultiPoolProfileWith([]models.Server{plain, mode}, func(s models.Server, id, tag string) (map[string]interface{}, error) {
		asked = append(asked, tag)
		return modeKey.outbound(tag), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := "member-" + ServiceTargetID(mode); len(asked) != 1 || asked[0] != want {
		t.Fatalf("the mode must be asked for its worker link once as %s: %v", want, asked)
	}
	if !strings.Contains(string(pool.RawProfile), `"address":"127.0.0.1"`) || !strings.Contains(string(pool.RawProfile), `"port":20001`) {
		t.Fatalf("the pool must reach the mode's worker over loopback: %s", pool.RawProfile)
	}
	poolKey, err := newServiceWorkerKey(20002)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serviceWorkerConfig(pool, nil, poolKey); err != nil {
		t.Fatalf("the pool worker refused a pool with a provider's mode: %v", err)
	}
	if _, err := MultiPoolProfile([]models.Server{plain, mode}); err == nil {
		t.Fatal("without a worker link a mode must not enter a pool")
	}
}
