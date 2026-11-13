package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"xkeen-panel/internal/cardcontroller"
)

type routerLoad struct {
	CPU      *float64  `json:"cpu_percent,omitempty"`
	Cores    int       `json:"cores,omitempty"`
	Load     []float64 `json:"load,omitempty"`
	RAMTotal uint64    `json:"ram_total_kib,omitempty"`
	RAMUsed  uint64    `json:"ram_used_kib,omitempty"`
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
	sampled  time.Time
	cpu      *float64
}

func NewDiagnosticsHandler(cards *cardcontroller.Controller) http.HandlerFunc {
	d := &diagnosticsHandler{cards: cards}
	return d.serve
}

func (d *diagnosticsHandler) load() routerLoad {
	stat, _ := os.ReadFile("/proc/stat")
	curr := readCPU(string(stat))
	d.mu.Lock()
	if time.Since(d.sampled) >= time.Second {
		if time.Since(d.sampled) < 30*time.Second {
			d.cpu = cpuPercent(d.previous, curr)
		} else {
			d.cpu = nil
		}
		d.previous, d.sampled = curr, time.Now()
	}
	result := routerLoad{CPU: d.cpu, Cores: curr.cores}
	d.mu.Unlock()
	mem, _ := os.ReadFile("/proc/meminfo")
	result.RAMTotal, result.RAMUsed = memoryUsage(string(mem))
	avg, _ := os.ReadFile("/proc/loadavg")
	var a, b, c float64
	if n, _ := fmt.Sscan(string(avg), &a, &b, &c); n == 3 {
		result.Load = []float64{a, b, c}
	}
	return result
}

func (d *diagnosticsHandler) serve(w http.ResponseWriter, r *http.Request) {
	result := struct {
		Load  routerLoad                  `json:"system"`
		Flows []cardcontroller.Connection `json:"connections"`
		Error string                      `json:"connections_error,omitempty"`
	}{Load: d.load(), Flows: []cardcontroller.Connection{}}
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
