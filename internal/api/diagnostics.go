package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"xkeen-panel/internal/cardcontroller"
	"xkeen-panel/internal/keenetic"
	"xkeen-panel/internal/xkeen"
)

type routerLoad struct {
	At          time.Time     `json:"at"`
	Temperature *float64      `json:"temperature_c,omitempty"`
	CPU         *float64      `json:"cpu_percent,omitempty"`
	Cores       int           `json:"cores,omitempty"`
	Load        []float64     `json:"load,omitempty"`
	RAMTotal    uint64        `json:"ram_total_kib,omitempty"`
	RAMUsed     uint64        `json:"ram_used_kib,omitempty"`
	WAN         []wanInterval `json:"wan,omitempty"`
}

type cpuSample struct {
	total, idle uint64
	cores       int
}

func readCPU(data string) (s cpuSample) {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || !strings.HasPrefix(fields[0], "cpu") {
			continue
		}
		if fields[0] != "cpu" {
			s.cores++
			continue
		}
		// guest and guest_nice are already counted in user and nice.
		for i, v := range fields[1:min(9, len(fields))] {
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return cpuSample{}
			}
			s.total += n
			if i == 3 || i == 4 {
				s.idle += n
			}
		}
	}
	return
}

func cpuPercent(prev, now cpuSample) *float64 {
	if prev.total == 0 || now.total <= prev.total || now.idle < prev.idle {
		return nil
	}
	ticks, idle := now.total-prev.total, now.idle-prev.idle
	if ticks < idle {
		return nil
	}
	value := float64(ticks-idle) * 100 / float64(ticks)
	return &value
}

func memoryUsage(data string) (uint64, uint64) {
	fields := map[string]uint64{}
	for _, line := range strings.Split(data, "\n") {
		var name string
		var value uint64
		if _, err := fmt.Sscan(line, &name, &value); err == nil {
			fields[name] = value
		}
	}
	total := fields["MemTotal:"]
	available, ok := fields["MemAvailable:"]
	if !ok {
		available = fields["MemFree:"] + fields["Cached:"] + fields["Buffers:"]
	}
	return total, total - min(total, available)
}

type diagnosticsHandler struct {
	cards       *cardcontroller.Controller
	mu          sync.Mutex
	previous    cpuSample
	history     []routerLoad
	wanPrevious map[string]keenetic.TrafficCounters
	wanAt       time.Time
	readWAN     func(context.Context) map[string]keenetic.TrafficCounters
}

// Netcraze exposes a number of on-board sensors. Display the hottest readable
// sensor, keeping missing readings distinct from a real zero.
func routerTemperature(paths []string) *float64 {
	var highest *float64
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 32)
		if err != nil || n < -40000 || n > 150000 {
			continue
		}
		value := float64(n) / 1000
		if highest == nil || value > *highest {
			highest = &value
		}
	}
	return highest
}

func NewDiagnosticsHandler(ctx context.Context, cards *cardcontroller.Controller, devices *DevicesHandler) http.HandlerFunc {
	d := &diagnosticsHandler{
		cards: cards,
		readWAN: func(ctx context.Context) map[string]keenetic.TrafficCounters {
			return devices.client().WANCounters(ctx)
		},
	}
	zones, _ := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
	hwmon, _ := filepath.Glob("/sys/class/hwmon/hwmon*/temp*_input")
	sensors := append(zones, hwmon...)
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		d.sample(ctx, sensors)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.sample(ctx, sensors)
			}
		}
	}()
	return d.serve
}

func (d *diagnosticsHandler) sample(ctx context.Context, sensors []string) {
	stat, _ := os.ReadFile("/proc/stat")
	curr := readCPU(string(stat))
	result := routerLoad{At: time.Now(), CPU: cpuPercent(d.previous, curr), Cores: curr.cores, Temperature: routerTemperature(sensors)}
	d.previous = curr
	mem, _ := os.ReadFile("/proc/meminfo")
	result.RAMTotal, result.RAMUsed = memoryUsage(string(mem))
	avg, _ := os.ReadFile("/proc/loadavg")
	var a, b, c float64
	if n, _ := fmt.Sscan(string(avg), &a, &b, &c); n == 3 {
		result.Load = []float64{a, b, c}
	}
	wanCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	counters := d.readWAN(wanCtx)
	cancel()
	now := time.Now()
	result.WAN = wanIntervals(d.wanPrevious, counters, now.Sub(d.wanAt))
	d.wanPrevious, d.wanAt = counters, now
	result.At = now
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.history) == 180 {
		copy(d.history, d.history[1:])
		d.history = d.history[:179]
	}
	d.history = append(d.history, result)
}

func (d *diagnosticsHandler) serve(w http.ResponseWriter, r *http.Request) {
	result := struct {
		Load     routerLoad                       `json:"system"`
		History  []routerLoad                     `json:"history"`
		Flows    []cardcontroller.Connection      `json:"connections"`
		Services []xkeen.ServiceName              `json:"services"`
		Error    string                           `json:"connections_error,omitempty"`
		Guard    *cardcontroller.GuardObservation `json:"guard,omitempty"`
	}{Flows: []cardcontroller.Connection{}, Services: xkeen.ServiceNames()}
	// Each page asks only for its half: the load charts need no connection
	// list, and the journal needs no chart history.
	wantLoad, wantFlows := r.URL.Query().Get("load") != "0", r.URL.Query().Get("connections") != "0"
	d.mu.Lock()
	if wantLoad {
		result.History = append([]routerLoad(nil), d.history...)
	}
	if n := len(d.history); n > 0 {
		result.Load = d.history[n-1]
	}
	d.mu.Unlock()
	if !wantFlows {
		writeJSON(w, http.StatusOK, result)
		return
	}
	if d.cards == nil {
		result.Error = "Для просмотра соединений нужен контроллер Mihomo."
	} else {
		guard := d.cards.GuardEvents()
		result.Guard = &guard
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		flows, err := d.cards.Connections(ctx)
		if err != nil {
			result.Error = "Список соединений Mihomo сейчас недоступен."
		} else {
			result.Flows = flows
		}
	}
	writeJSON(w, http.StatusOK, result)
}
