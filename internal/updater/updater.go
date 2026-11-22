package updater

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"xkeen-panel/internal/releasesig"
)

// ErrLocked is a build policy, not a user preference or a version check.
var ErrLocked = errors.New("обновление и откат кода заблокированы в этой сборке, чтобы сохранить доработки панели")

const (
	DefaultRepo = "Sgadmer/xkeen-panel"

	channelStable  = "stable"
	channelPreview = "preview"

	// The page offers this many of the newest versions to pick from
	versionsShown = 30

	checkEvery = 12 * time.Hour
	tickEvery  = 10 * time.Minute

	// The new binary must prove itself before the guard gives up on it
	confirmAfter = 45 * time.Second
	guardDelay   = 2 * time.Minute
)

// Kept in data/ so the UI can change them without rewriting config.yaml and losing its comments.
type Settings struct {
	Auto bool `json:"auto"`
	// The choice was made: by the owner with the switch, or in the first-run
	// wizard. The wizard offers automatic updates only while this is unset, so
	// an update of the panel never changes what a router already has.
	AutoSet bool `json:"auto_set,omitempty"`
	// "preview" when the owner asked for beta versions too; empty means stable only
	Channel    string `json:"channel,omitempty"`
	Repository string `json:"repository,omitempty"`

	// Failed to start, or newer than the version the owner picked by hand:
	// automatic updates leave it alone, the button still installs it
	Skip string `json:"skip,omitempty"`
}

// Version is one release the owner can pick from the list.
type Version struct {
	Tag         string    `json:"tag"`
	PublishedAt time.Time `json:"published_at"`
	Prerelease  bool      `json:"prerelease"`
}

type State struct {
	Repository string   `json:"repository"`
	Channel    string   `json:"channel"`
	Locked     bool     `json:"locked"`
	Current    string   `json:"current"`
	Latest     *Release `json:"latest,omitempty"`
	// Signed releases of the chosen channel, newest first
	Versions    []Version `json:"versions,omitempty"`
	Available   bool      `json:"available"`
	Supported   bool      `json:"supported"`
	Reason      string    `json:"reason,omitempty"` // why updates are unavailable on this build
	Auto        bool      `json:"auto"`
	AutoHour    int       `json:"auto_hour"`
	Skip        string    `json:"skip,omitempty"`
	Updating    bool      `json:"updating"`
	Installing  string    `json:"installing,omitempty"` // the release being installed right now
	LastCheck   time.Time `json:"last_check,omitempty"`
	CheckError  string    `json:"check_error,omitempty"`
	ApplyError  string    `json:"apply_error,omitempty"`
	FailedStart string    `json:"failed_start,omitempty"` // release that did not come up and was rolled back
}

type Options struct {
	Locked       bool // immutable build policy; never read from YAML or update.json
	Current      string
	BinPath      string
	DataDir      string
	InitScript   string
	RequiredFlag string // command-line option used by the installed init script
	AutoHour     int
	Repo         string
	APIBase      string
	Client       *http.Client
	Log          func(format string, args ...interface{})
	Publish      func(State)
	Restart      func() error
	Busy         func() bool // the core is restarting; not the moment to restart the panel too
}

type Updater struct {
	locked       bool // copied once at construction; there is intentionally no setter
	current      string
	binPath      string
	dataDir      string
	initScript   string
	requiredFlag string
	autoHour     int
	repo         string
	apiBase      string
	asset        string
	keys         []ed25519.PublicKey // release keys; a release signed by none of them is not installed
	client       *http.Client
	logf         func(format string, args ...interface{})
	publish      func(State)
	restart      func() error
	busy         func() bool

	guardDelay   time.Duration
	confirmAfter time.Duration

	mu          sync.Mutex
	settings    Settings
	latest      *Release
	releases    []Release // what the last check found, newest first
	lastCheck   time.Time
	checkErr    string
	applyErr    string
	updating    bool
	installing  string
	failedStart string
	attempted   map[string]time.Time
}

func New(opts Options) *Updater {
	u := &Updater{
		locked:       opts.Locked,
		current:      opts.Current,
		binPath:      opts.BinPath,
		dataDir:      opts.DataDir,
		initScript:   opts.InitScript,
		requiredFlag: opts.RequiredFlag,
		autoHour:     opts.AutoHour,
		repo:         opts.Repo,
		apiBase:      opts.APIBase,
		asset:        currentAsset(),
		client:       opts.Client,
		logf:         opts.Log,
		publish:      opts.Publish,
		restart:      opts.Restart,
		busy:         opts.Busy,
		attempted:    map[string]time.Time{},

		guardDelay:   guardDelay,
		confirmAfter: confirmAfter,
	}
	if u.repo == "" {
		u.repo = DefaultRepo
	}
	if u.apiBase == "" {
		u.apiBase = "https://api.github.com"
	}
	if u.client == nil {
		u.client = &http.Client{Timeout: 5 * time.Minute}
	}

	if u.locked {
		return u
	}
	// A build whose keys cannot be read installs nothing: Verify refuses an empty list.
	keys, err := releasesig.Trusted()
	if err != nil {
		u.log("[UPDATE] Ключи проверки выпусков не прочитаны: %v", err)
	}
	u.keys = keys
	var loaded Settings
	if err := readJSON(u.settingsPath(), &loaded); err != nil {
		if !os.IsNotExist(err) {
			u.log("[UPDATE] Настройки обновлений не прочитаны (%v) — действуют настройки по умолчанию", err)
		}
	} else if loaded.Repository == u.repo {
		// Choices made for another source of updates are not carried over.
		if loaded.Channel != channelPreview {
			loaded.Channel = ""
		}
		u.settings = loaded
	}
	u.settings.Repository = u.repo
	// A release that is not ahead of the running version has nothing left to
	// skip, for example after a build was put on the router past the updater.
	if skip, ok := parseSemver(u.settings.Skip); ok {
		if cur, ok := parseSemver(u.current); ok && !newer(cur, skip) {
			u.settings.Skip = ""
		}
	}

	return u
}

func (u *Updater) settingsPath() string { return filepath.Join(u.dataDir, "update.json") }

func (u *Updater) log(format string, args ...interface{}) {
	if u.logf != nil {
		u.logf(format, args...)
	}
}

func (u *Updater) supported() (bool, string) {
	if u.locked {
		return false, ErrLocked.Error()
	}
	if _, ok := parseSemver(u.current); !ok {
		return false, "сборка без версии (dev) не обновляется"
	}
	if u.asset == "" {
		return false, "для этой платформы релизы не публикуются"
	}
	if u.binPath == "" {
		return false, "не удалось определить путь к бинарю"
	}
	return true, ""
}

func (u *Updater) State() State {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.stateLocked()
}

func (u *Updater) stateLocked() State {
	if u.locked {
		// No disk probing, cached release or persisted preference can expose an
		// install/rollback action when this binary has updates compiled out.
		return State{Locked: true, Current: u.current, Reason: ErrLocked.Error(), AutoHour: u.autoHour}
	}
	supported, reason := u.supported()

	state := State{
		Repository:  u.repo,
		Channel:     u.updateChannel(),
		Current:     u.current,
		Latest:      u.latest,
		Supported:   supported,
		Reason:      reason,
		Auto:        u.settings.Auto,
		AutoHour:    u.autoHour,
		Skip:        u.settings.Skip,
		Updating:    u.updating,
		Installing:  u.installing,
		LastCheck:   u.lastCheck,
		CheckError:  u.checkErr,
		ApplyError:  u.applyErr,
		FailedStart: u.failedStart,
	}

	for i, release := range u.releases {
		if i == versionsShown {
			break
		}
		state.Versions = append(state.Versions, Version{Tag: release.Tag, PublishedAt: release.PublishedAt, Prerelease: release.Prerelease})
	}

	if u.latest != nil {
		cur, okCur := parseSemver(u.current)
		next, okNext := parseSemver(u.latest.Tag)
		state.Available = okCur && okNext && newer(cur, next)
	}

	return state
}

func (u *Updater) notify() {
	if u.publish != nil {
		u.publish(u.State())
	}
}

func (u *Updater) Check(ctx context.Context) (State, error) {
	if u.locked {
		return u.State(), ErrLocked
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	u.mu.Lock()
	channel := u.updateChannel()
	u.mu.Unlock()

	releases, err := u.fetchPublished(ctx, channel == channelPreview)

	u.mu.Lock()
	u.lastCheck = time.Now()
	if err != nil {
		u.checkErr = err.Error()
	} else if channel == u.updateChannel() {
		// An answer for a channel the owner has just left is dropped
		u.checkErr = ""
		u.releases, u.latest = releases, nil
		if len(releases) > 0 {
			latest := releases[0]
			u.latest = &latest
		}
	}
	state := u.stateLocked()
	u.mu.Unlock()

	u.notify()

	if err != nil {
		return state, fmt.Errorf("проверка обновлений: %w", err)
	}
	return state, nil
}

// Apply installs the newest release of the channel.
func (u *Updater) Apply() error { return u.start("") }

// ApplyVersion installs the release the owner picked from the list. It may be
// older than the running one: every listed release is signed, so the way
// forward stays open from any of them.
func (u *Updater) ApplyVersion(tag string) error {
	if u.locked {
		return ErrLocked
	}
	if tag == "" {
		return fmt.Errorf("выберите версию")
	}
	return u.start(tag)
}

func (u *Updater) start(tag string) error {
	if u.locked {
		return ErrLocked
	}
	if ok, reason := u.supported(); !ok {
		return fmt.Errorf("обновление недоступно: %s", reason)
	}

	u.mu.Lock()
	if u.updating {
		u.mu.Unlock()
		return fmt.Errorf("обновление уже выполняется")
	}
	var release Release
	if tag == "" {
		if !u.stateLocked().Available {
			u.mu.Unlock()
			return fmt.Errorf("нет более новой версии — сначала проверьте обновления")
		}
		release = *u.latest
	} else {
		if tag == u.current {
			u.mu.Unlock()
			return fmt.Errorf("версия %s уже установлена", tag)
		}
		// Only what the last check accepted can be asked for
		for _, listed := range u.releases {
			if listed.Tag == tag {
				release = listed
				break
			}
		}
		if release.Tag == "" {
			u.mu.Unlock()
			return fmt.Errorf("этой версии нет в списке — сначала проверьте обновления")
		}
	}
	u.updating = true
	u.installing = release.Tag
	u.applyErr = ""
	u.attempted[release.Tag] = time.Now()
	u.mu.Unlock()

	u.notify()
	go u.runApply(release)

	return nil
}

func (u *Updater) runApply(release Release) {
	if u.locked {
		return
	}
	u.log("[UPDATE] Устанавливаю %s (сейчас %s)", release.Tag, u.current)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if err := u.install(ctx, release); err != nil {
		u.fail(fmt.Errorf("обновление до %s не установлено: %w", release.Tag, err))
		return
	}

	u.mu.Lock()
	// The owner picked a version while a newer one exists. Automatic updates
	// must not put that newer one back the next night; the one after it is free.
	if u.latest != nil {
		picked, okPicked := parseSemver(release.Tag)
		latest, okLatest := parseSemver(u.latest.Tag)
		if okPicked && okLatest && newer(picked, latest) {
			u.settings.Skip = u.latest.Tag
			if err := writeJSON(u.settingsPath(), u.settings); err != nil {
				u.log("[UPDATE] Не удалось сохранить настройки: %v", err)
			}
		}
	}
	u.mu.Unlock()

	u.log("[UPDATE] %s установлена, перезапускаю панель", release.Tag)
	if err := u.restart(); err != nil {
		u.fail(fmt.Errorf("новая версия установлена, но панель не перезапустилась: %w — перезапустите её вручную", err))
	}
}

func (u *Updater) fail(err error) {
	u.log("[UPDATE] %v", err)
	u.mu.Lock()
	u.updating = false
	u.installing = ""
	u.applyErr = err.Error()
	u.mu.Unlock()
	u.notify()
}

// Checks keep running either way, so the UI can still offer an update by hand.
func (u *Updater) SetAuto(auto bool) error { return u.setAuto(auto, false) }

// AutoOffered reports whether the first-run wizard may still offer automatic
// updates: they are off and nobody has chosen yet.
func (u *Updater) AutoOffered() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return !u.locked && !u.settings.Auto && !u.settings.AutoSet
}

// SetAutoDefault records the wizard's offer. It applies once: a later run of
// the wizard does not undo what the owner has chosen since.
func (u *Updater) SetAutoDefault(auto bool) error { return u.setAuto(auto, true) }

func (u *Updater) setAuto(auto, offer bool) error {
	if u.locked {
		return ErrLocked
	}
	u.mu.Lock()
	if offer && (u.settings.Auto || u.settings.AutoSet) {
		u.mu.Unlock()
		return nil
	}
	old := u.settings
	u.settings.Auto, u.settings.AutoSet = auto, true
	err := writeJSON(u.settingsPath(), u.settings)
	if err != nil {
		u.settings = old
	}
	u.mu.Unlock()

	u.notify()
	return err
}

// SetChannel chooses between stable releases only and stable plus beta ones.
// What the last check found belonged to the other channel and is forgotten.
func (u *Updater) SetChannel(channel string) error {
	if u.locked {
		return ErrLocked
	}
	if channel != channelStable && channel != channelPreview {
		return fmt.Errorf("неизвестный канал обновлений")
	}
	if channel == channelStable {
		channel = ""
	}
	u.mu.Lock()
	old := u.settings.Channel
	u.settings.Channel = channel
	err := writeJSON(u.settingsPath(), u.settings)
	if err != nil {
		u.settings.Channel = old
	} else if old != channel {
		u.latest, u.releases, u.lastCheck, u.checkErr = nil, nil, time.Time{}, ""
	}
	u.mu.Unlock()

	u.notify()
	return err
}

func (u *Updater) Startup(ctx context.Context, healthy func() bool) {
	if u.locked {
		return
	}
	var failed pendingMarker
	if err := readJSON(u.failedPath(), &failed); err == nil {
		os.Remove(u.failedPath())
		u.log("[UPDATE] %s не запустилась и была откачена на %s", failed.To, u.current)

		u.mu.Lock()
		u.failedStart = failed.To
		u.settings.Skip = failed.To
		if err := writeJSON(u.settingsPath(), u.settings); err != nil {
			u.log("[UPDATE] Не удалось сохранить настройки: %v", err)
		}
		u.mu.Unlock()
	}

	var pending pendingMarker
	if err := readJSON(u.pendingPath(), &pending); err != nil {
		return
	}
	if pending.To != u.current {
		os.Remove(u.pendingPath())
		return
	}

	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(u.confirmAfter):
		}
		if !healthy() {
			u.log("[UPDATE] %s запущена, но не отвечает — откат выполнит сторож", u.current)
			return
		}
		if err := os.Remove(u.pendingPath()); err != nil && !os.IsNotExist(err) {
			u.log("[UPDATE] Не удалось снять маркер обновления: %v", err)
			return
		}
		u.log("[UPDATE] Обновление с %s до %s завершено", pending.From, u.current)
	}()
}

func (u *Updater) Run(ctx context.Context) {
	if u.locked {
		return
	}
	if ok, reason := u.supported(); !ok {
		u.log("[UPDATE] Автообновление недоступно: %s", reason)
		return
	}

	// Stagger the first check so routers updated together do not all hit GitHub at once
	first := time.Minute + time.Duration(rand.Intn(120))*time.Second
	select {
	case <-ctx.Done():
		return
	case <-time.After(first):
	}

	u.tick(ctx, time.Now())

	ticker := time.NewTicker(tickEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			u.tick(ctx, now)
		}
	}
}

func (u *Updater) tick(ctx context.Context, now time.Time) {
	if u.locked {
		return
	}
	u.mu.Lock()
	due := now.Sub(u.lastCheck) >= checkEvery
	u.mu.Unlock()

	if due {
		if _, err := u.Check(ctx); err != nil {
			u.log("[UPDATE] %v", err)
			return
		}
	}

	if !u.shouldAutoApply(now) {
		return
	}

	if err := u.Apply(); err != nil {
		u.log("[UPDATE] Автообновление: %v", err)
	}
}

func (u *Updater) shouldAutoApply(now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()

	state := u.stateLocked()
	if !state.Auto || !state.Available || state.Updating || !state.Supported {
		return false
	}
	if now.Hour() != u.autoHour {
		return false
	}
	if state.Latest.Tag == u.settings.Skip {
		return false
	}
	// A release that failed to install is retried the next night, not every tick
	if at, ok := u.attempted[state.Latest.Tag]; ok && now.Sub(at) < 20*time.Hour {
		return false
	}
	if u.busy != nil && u.busy() {
		return false
	}
	return true
}
