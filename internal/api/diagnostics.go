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
)

type routerLoad struct {
	At          time.Time `json:"at"`
	Temperature *float64  `json:"temperature_c,omitempty"`
	CPU         *float64  `json:"cpu_percent,omitempty"`
	Cores       int       `json:"cores,omitempty"`
	Load        []float64 `json:"load,omitempty"`
	RAMTotal    uint64    `json:"ram_total_kib,omitempty"`
	RAMUsed     uint64    `json:"ram_used_kib,omitempty"`
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
	cards    *cardcontroller.Controller
	mu       sync.Mutex
	previous cpuSample
	history  []routerLoad
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

func NewDiagnosticsHandler(ctx context.Context, cards *cardcontroller.Controller) http.HandlerFunc {
	d := &diagnosticsHandler{cards: cards}
	zones, _ := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
	hwmon, _ := filepath.Glob("/sys/class/hwmon/hwmon*/temp*_input")
	sensors := append(zones, hwmon...)
	d.sample(sensors)
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.sample(sensors)
			}
		}
	}()
	return d.serve
}

func (d *diagnosticsHandler) sample(sensors []string) {
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
		Load    routerLoad                  `json:"system"`
		History []routerLoad                `json:"history"`
		Flows   []cardcontroller.Connection `json:"connections"`
		Error   string                      `json:"connections_error,omitempty"`
	}{Flows: []cardcontroller.Connection{}}
	d.mu.Lock()
	result.History = append([]routerLoad(nil), d.history...)
	d.mu.Unlock()
	if len(result.History) > 0 {
		result.Load = result.History[len(result.History)-1]
	}
	if d.cards == nil {
		result.Error = "Для просмотра соединений нужен контроллер Mihomo."
	} else {
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
