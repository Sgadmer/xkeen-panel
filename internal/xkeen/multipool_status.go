package xkeen

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The socket lives under the worker's 0700 directory, including when its
// member generation changes. No HTTP metrics listener is opened on the LAN.
func poolStatusSocket(base, id string, port int) string {
	if !profileHashPattern.MatchString(id) || port < 1 || port > 65535 || !filepath.IsAbs(base) {
		return ""
	}
	path := filepath.Join(base, "p-"+id[:16]+"-"+strconv.Itoa(port)+".sock")
	if len(path) > 102 {
		return ""
	}
	return path
}

func preparePoolStatusSocket(path string) error {
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || st.Mode()&os.ModeSocket == 0 {
		return errors.New("путь состояния пула занят")
	}
	conn, err := net.DialTimeout("unix", path, 250*time.Millisecond)
	if err == nil {
		conn.Close()
		return errors.New("сокет состояния пула занят")
	}
	return os.Remove(path)
}

func addPoolMetrics(cfg map[string]interface{}, socket string) {
	const tag = "pool-observations"
	cfg["stats"] = map[string]interface{}{}
	cfg["metrics"] = map[string]interface{}{"tag": tag}
	cfg["inbounds"] = append(asSlice(cfg["inbounds"]), map[string]interface{}{
		"tag": tag, "protocol": "http", "listen": socket,
		"settings": map[string]interface{}{"allowTransparent": true},
	})
	routing := mapOf(cfg["routing"])
	routing["rules"] = append([]interface{}{map[string]interface{}{"type": "field", "inboundTag": []string{tag}, "outboundTag": tag}}, asSlice(routing["rules"])...)
}

type memberObservation struct {
	Alive bool
	Delay int64
}

// Match Xray's leastPing strategy for this panel-generated worker only.
// Xray doesn't expose the tie order over metrics, so equal leaders have
// no unambiguous member until a subsequent observation.
func measuredPoolMember(entries map[string]memberObservation) string {
	id := ""
	best := int64(99999999)
	for tag, v := range entries {
		if !v.Alive || !IsProfileInternalTag(tag) {
			continue
		}
		member, ok := strings.CutPrefix(tag[69:], "ob-member-")
		if !ok || !profileHashPattern.MatchString(member) {
			continue
		}
		if v.Delay < best {
			id, best = member, v.Delay
		} else if v.Delay == best {
			id = ""
		}
	}
	return id
}

func CardPoolMember(ctx context.Context, rt Runtime, id string, port int) string {
	socket := poolStatusSocket(filepath.Join(filepath.Dir(rt.XrayConfDir), "xkeen-panel-cards"), id, port)
	if socket == "" {
		return ""
	}
	return readPoolMetrics(ctx, socket)
}

func readPoolMetrics(ctx context.Context, socket string) string {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/debug/vars", nil)
	res, err := transport.RoundTrip(req)
	if err != nil {
		return ""
	}
	defer res.Body.Close()
	var state struct{ Observatory map[string]memberObservation }
	if res.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&state) != nil {
		return ""
	}
	return measuredPoolMember(state.Observatory)
}
