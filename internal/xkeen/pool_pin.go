package xkeen

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// A pool worker measures its members itself, but by its last answer only, so
// on its own it jumps between servers whose numbers are close. The panel keeps
// the median of the recent answers (see ping.go) and pins every pool to the
// member with the best one through the worker's routing API. The API listens
// on loopback only, and a worker has no direct exit to route anything to.

// ErrPoolNoAPI marks a pool worker started without the routing API.
var ErrPoolNoAPI = errors.New("ядро пула запущено без канала управления")

var poolPins = struct {
	sync.Mutex
	member map[string]string // by the worker's status socket
}{member: map[string]string{}}

// preparePoolAPIPort gives a pool worker a free loopback port for its API,
// keeping the one it had while nothing else holds it.
func preparePoolAPIPort(dir string, key *serviceWorkerKey) error {
	if key.APIPort > 0 {
		if l, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(key.APIPort))); err == nil {
			l.Close()
			return nil
		}
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("не удалось выделить порт управления пулом")
	}
	key.APIPort = l.Addr().(*net.TCPAddr).Port
	l.Close()
	data, err := json.Marshal(key)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, "identity"), data, 0600)
}

func addPoolAPI(cfg map[string]interface{}, port int) {
	cfg["api"] = map[string]interface{}{
		"tag": "api", "listen": net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		"services": []interface{}{"RoutingService"},
	}
}

// PinPoolMember makes the pool worker id on port carry traffic through one
// member; an empty member lets the worker choose by itself again.
func PinPoolMember(ctx context.Context, rt Runtime, id string, port int, member string) error {
	worker, err := cardWorkerRuntime(rt)
	if err != nil {
		return err
	}
	addr := poolAPIAddress(worker, id, port)
	if addr == "" {
		return ErrPoolNoAPI
	}
	socket := poolStatusSocket(filepath.Join(filepath.Dir(rt.XrayConfDir), "xkeen-panel-cards"), id, port)
	// Inside the worker every tag carries the namespace of its generation; the
	// worker's own report names them.
	balancer, target := "", ""
	for tag := range readPoolObservations(ctx, socket) {
		if !IsProfileInternalTag(tag) {
			continue
		}
		balancer = tag[:69] + "bal-pool"
		if tag[69:] == "ob-member-"+member {
			target = tag
		}
	}
	if balancer == "" || member != "" && target == "" {
		return fmt.Errorf("ядро пула не сообщило о сервере %s", member)
	}
	args := []string{"bo", "-s", addr, "-b", balancer}
	if member == "" {
		args = append(args, "-r")
	} else {
		args = append(args, target)
	}
	if _, err := xrayAPI(worker, args...); err != nil {
		return fmt.Errorf("не удалось выбрать сервер пула: %w", err)
	}
	poolPins.Lock()
	defer poolPins.Unlock()
	if member == "" {
		delete(poolPins.member, socket)
	} else {
		poolPins.member[socket] = member
	}
	return nil
}

func pinnedPoolMember(socket string) string {
	poolPins.Lock()
	defer poolPins.Unlock()
	return poolPins.member[socket]
}

func poolAPIAddress(worker Runtime, id string, port int) string {
	root, err := serviceWorkerRoot(worker)
	if err != nil || !profileHashPattern.MatchString(id) {
		return ""
	}
	paths, _ := filepath.Glob(filepath.Join(root, id, "*", "identity"))
	for _, path := range paths {
		var key serviceWorkerKey
		if data, err := os.ReadFile(path); err == nil && json.Unmarshal(data, &key) == nil && key.Port == port && key.APIPort > 0 {
			return net.JoinHostPort("127.0.0.1", strconv.Itoa(key.APIPort))
		}
	}
	return ""
}
