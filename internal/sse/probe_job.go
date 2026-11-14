package sse

import (
	"context"
	"errors"
	"sync"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

type Measurement struct {
	ID          int       `json:"id"`
	Latency     int       `json:"latency_ms"`
	LastChecked time.Time `json:"last_checked"`
}

type ProbeProgress struct {
	Run     uint64        `json:"run"`
	Running bool          `json:"running"`
	IDs     []int         `json:"ids"`
	Results []Measurement `json:"results"`
	Error   string        `json:"error,omitempty"`
}

type probeRun struct {
	progress ProbeProgress
	done     chan struct{}
	seen     map[int]bool
	checked  []models.Server
}

var ErrPoolUpdate = errors.New("замеры сохранены, состав пула ещё не обновлён")
var ErrProbeBusy = errors.New("HTTPS-проверка уже выполняется")
var ErrProbeIDs = errors.New("выберите существующие серверы для проверки")

type ProbeJobs struct {
	mu      sync.Mutex
	run     *probeRun
	sub     *xkeen.SubscriptionManager
	options xkeen.ProbeOptions
	probe   func([]models.Server, xkeen.ProbeOptions) ([]models.Server, error)
	save    func(context.Context, []models.Server) error
}

func NewProbeJobs(sub *xkeen.SubscriptionManager, options xkeen.ProbeOptions, probe func([]models.Server, xkeen.ProbeOptions) ([]models.Server, error), save func(context.Context, []models.Server) error) *ProbeJobs {
	if save == nil {
		save = func(_ context.Context, results []models.Server) error { return sub.UpdateLatencies(results) }
	}
	return &ProbeJobs{sub: sub, options: options, probe: probe, save: save}
}

func (j *ProbeJobs) start() *probeRun {
	r, _ := j.startFor(nil)
	return r
}

func (j *ProbeJobs) startFor(ids []int) (*probeRun, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.run != nil && j.run.progress.Running {
		if ids != nil {
			return nil, ErrProbeBusy
		}
		return j.run, nil
	}
	servers := j.sub.GetServers()
	if ids != nil {
		wanted := make(map[int]bool, len(ids))
		for _, id := range ids {
			wanted[id] = true
		}
		selected := make([]models.Server, 0, len(wanted))
		for _, server := range servers {
			if wanted[server.ID] {
				selected = append(selected, server)
				delete(wanted, server.ID)
			}
		}
		if len(selected) == 0 || len(wanted) > 0 {
			return nil, ErrProbeIDs
		}
		servers = selected
	}
	next := uint64(1)
	if j.run != nil {
		next = j.run.progress.Run + 1
	}
	r := &probeRun{progress: ProbeProgress{Run: next, Running: true, IDs: make([]int, 0, len(servers)), Results: []Measurement{}}, seen: make(map[int]bool), done: make(chan struct{})}
	for _, server := range servers {
		r.progress.IDs = append(r.progress.IDs, server.ID)
	}
	j.run = r
	go j.execute(r, servers)
	return r, nil
}

func (j *ProbeJobs) Start() ProbeProgress { return j.snapshot(j.start()) }

func (j *ProbeJobs) StartSelected(ids []int) (ProbeProgress, error) {
	if len(ids) == 0 {
		return ProbeProgress{}, ErrProbeIDs
	}
	r, err := j.startFor(ids)
	if err != nil {
		return ProbeProgress{}, err
	}
	return j.snapshot(r), nil
}

func (j *ProbeJobs) Snapshot() ProbeProgress { return j.snapshot(nil) }

func (j *ProbeJobs) snapshot(r *probeRun) ProbeProgress {
	j.mu.Lock()
	defer j.mu.Unlock()
	if r == nil {
		r = j.run
	}
	if r == nil {
		return ProbeProgress{IDs: []int{}, Results: []Measurement{}}
	}
	out := r.progress
	out.Results = append([]Measurement{}, r.progress.Results...)
	return out
}

func (j *ProbeJobs) execute(r *probeRun, servers []models.Server) {
	options := j.options
	if options.Concurrency < 1 {
		options.Concurrency = 3
	}
	if options.Timeout < 2*time.Second {
		options.Timeout = 8 * time.Second
	}
	// Each complete profile needs an isolated core and its own validation budget.
	// The individual core invocations also enforce their own size-based timeout.
	profiles := 0
	for _, s := range servers {
		if len(s.RawProfile) != 0 {
			profiles++
		}
	}
	parent := options.Context
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute+time.Duration(profiles)*50*time.Second+time.Duration(len(servers)/min(6, options.Concurrency)+1)*min(options.Timeout, 20*time.Second))
	defer cancel()
	options.Context = ctx
	options.OnResult = func(s models.Server) {
		j.mu.Lock()
		defer j.mu.Unlock()
		if r.seen[s.ID] {
			return
		}
		r.seen[s.ID] = true
		r.progress.Results = append(r.progress.Results, Measurement{ID: s.ID, Latency: s.Latency, LastChecked: s.LastChecked})
	}
	var checked []models.Server
	var err error
	if len(servers) > 0 {
		checked, err = j.probe(servers, options)
	}
	message := ""
	if err != nil {
		message = "Не удалось завершить HTTPS-проверку. Проверьте состояние проверочного ядра."
	} else if len(servers) > 0 {
		for _, result := range checked {
			options.OnResult(result)
		}
		if err = j.save(ctx, checked); errors.Is(err, ErrPoolUpdate) {
			message = "Замеры сохранены. Обновить состав пула пока не удалось."
		} else if err != nil {
			message = "Проверка завершена, но сохранить замеры не удалось."
		}
	}
	for i := range checked {
		// Compatibility responses only need public metadata after persistence.
		checked[i].RawURI, checked[i].RawOutbound, checked[i].RawProfile = "", nil, nil
	}
	j.mu.Lock()
	// Compatibility callers waiting on this run receive its own results.
	r.checked, r.progress.Error, r.progress.Running = checked, message, false
	close(r.done)
	j.mu.Unlock()
}

func (j *ProbeJobs) Wait(ctx context.Context) ([]models.Server, string) {
	r := j.start()
	select {
	case <-r.done:
		return r.checked, r.progress.Error
	case <-ctx.Done():
		return nil, "Ожидание прервано. Проверка продолжается на роутере."
	}
}
