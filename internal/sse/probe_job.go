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
	// Stopped marks a run the owner stopped; its finished measurements are kept.
	Stopped bool `json:"stopped,omitempty"`
	// Background marks a run the panel started itself.
	Background bool `json:"background,omitempty"`
}

type probeRun struct {
	progress ProbeProgress
	done     chan struct{}
	seen     map[int]bool
	checked  []models.Server
	finished []models.Server
	cancel   context.CancelFunc
}

var ErrPoolUpdate = errors.New("замеры сохранены, состав пула ещё не обновлён")
var ErrProbeBusy = errors.New("проверка серверов уже выполняется")
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
	r, _ := j.startFor(nil, false)
	return r
}

func (j *ProbeJobs) startFor(ids []int, background bool) (*probeRun, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.run != nil && j.run.progress.Running {
		if ids != nil || background {
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
		if len(selected) == 0 || len(wanted) > 0 && !background {
			return nil, ErrProbeIDs
		}
		servers = selected
	}
	next := uint64(1)
	if j.run != nil {
		next = j.run.progress.Run + 1
	}
	r := &probeRun{progress: ProbeProgress{Run: next, Running: true, Background: background, IDs: make([]int, 0, len(servers)), Results: []Measurement{}}, seen: make(map[int]bool), done: make(chan struct{})}
	for _, server := range servers {
		r.progress.IDs = append(r.progress.IDs, server.ID)
	}
	j.run = r
	go j.execute(r, servers)
	return r, nil
}

func (j *ProbeJobs) Start() ProbeProgress {
	j.stopBackground()
	return j.snapshot(j.start())
}

// stopBackground lets the owner's check replace a background one instead of
// waiting for it; what the background run measured so far is kept.
func (j *ProbeJobs) stopBackground() {
	j.mu.Lock()
	background := j.run != nil && j.run.progress.Running && j.run.progress.Background
	j.mu.Unlock()
	if background {
		j.Cancel()
	}
}

func (j *ProbeJobs) StartSelected(ids []int) (ProbeProgress, error) {
	if len(ids) == 0 {
		return ProbeProgress{}, ErrProbeIDs
	}
	j.stopBackground()
	r, err := j.startFor(ids, false)
	if err != nil {
		return ProbeProgress{}, err
	}
	return j.snapshot(r), nil
}

// StartBackground measures the given servers, or all of them for nil, unless
// a run is already going. Servers that vanished meanwhile are skipped.
func (j *ProbeJobs) StartBackground(ids []int) bool {
	if ids != nil && len(ids) == 0 {
		return false
	}
	_, err := j.startFor(ids, true)
	return err == nil
}

// Running reports whether a check is going now.
func (j *ProbeJobs) Running() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.run != nil && j.run.progress.Running
}

// Cancel stops the current run. Measurements finished before the stop are
// saved like those of a complete run; servers still in flight keep their
// previous result.
func (j *ProbeJobs) Cancel() ProbeProgress {
	j.mu.Lock()
	r := j.run
	if r != nil && r.progress.Running && !r.progress.Stopped {
		r.progress.Stopped = true
		if r.cancel != nil {
			r.cancel()
		}
	}
	j.mu.Unlock()
	if r != nil {
		select {
		case <-r.done:
		case <-time.After(5 * time.Second):
		}
	}
	return j.snapshot(r)
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
	// Two files of up to 20 s each per node in the worst case.
	perNode := 2 * min(max(options.Timeout, 5*time.Second), 20*time.Second)
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute+time.Duration(profiles)*50*time.Second+time.Duration(len(servers)/min(xkeen.MaxProbeConcurrency, options.Concurrency)+1)*perNode)
	defer cancel()
	j.mu.Lock()
	r.cancel = cancel
	j.mu.Unlock()
	options.Context = ctx
	options.OnResult = func(s models.Server) {
		j.mu.Lock()
		defer j.mu.Unlock()
		// After a stop the nodes still in flight fail only because their
		// connection was cut; that is not their result.
		if r.seen[s.ID] || r.progress.Stopped {
			return
		}
		r.seen[s.ID] = true
		r.finished = append(r.finished, s)
		r.progress.Results = append(r.progress.Results, Measurement{ID: s.ID, Latency: s.Latency, LastChecked: s.LastChecked})
	}
	var checked []models.Server
	var err error
	if len(servers) > 0 {
		checked, err = j.probe(servers, options)
	}
	j.mu.Lock()
	stopped := r.progress.Stopped
	if stopped {
		checked, err = append([]models.Server(nil), r.finished...), nil
	}
	j.mu.Unlock()
	message := ""
	if err != nil {
		message = "Не удалось завершить проверку серверов. Проверьте состояние проверочного ядра."
	} else if len(checked) > 0 {
		if !stopped {
			for _, result := range checked {
				options.OnResult(result)
			}
		}
		// The run's own deadline may be spent or cancelled; saving gets its own.
		saveCtx, saveCancel := context.WithTimeout(parent, 2*time.Minute)
		if err = j.save(saveCtx, checked); errors.Is(err, ErrPoolUpdate) {
			message = "Замеры сохранены. Обновить состав пула пока не удалось."
		} else if err != nil {
			message = "Проверка завершена, но сохранить замеры не удалось."
		}
		saveCancel()
	}
	for i := range checked {
		// Compatibility responses only need public metadata after persistence.
		checked[i].RawURI, checked[i].RawOutbound, checked[i].RawProfile = "", nil, nil
	}
	j.mu.Lock()
	// Compatibility callers waiting on this run receive its own results.
	r.checked, r.progress.Error, r.progress.Running = checked, message, false
	r.finished = nil
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
