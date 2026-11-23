package models

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Config is the application configuration (config.yaml).
type Config struct {
	Port          int    `yaml:"port"`
	DataDir       string `yaml:"data_dir"`
	XKeenPath     string `yaml:"xkeen_path"`
	OutboundsFile string `yaml:"outbounds_file"`
	CheckInterval int    `yaml:"check_interval"`
	CheckURL      string `yaml:"check_url"`
	MaxFails      int    `yaml:"max_fails"`
	LogFile       string `yaml:"log_file"`

	// XKeen layout. Every field is optional — the panel detects the layout of
	// both the 1.x (S24xray) and 2.x (S05xkeen) installs on startup.
	InitScript    string `yaml:"init_script"` // deprecated: kept so old config.yaml still loads
	XrayConfigDir string `yaml:"xray_config_dir"`
	RoutingFile   string `yaml:"routing_file"`
	MihomoConfig  string `yaml:"mihomo_config"`
	XkeenJSON     string `yaml:"xkeen_json"`
	XrayAPIAddr   string `yaml:"xray_api_addr"`
	ProbeAddr     string `yaml:"probe_addr"` // local socks inbound the watchdog checks the proxy through

	// Autopilot: latency probing and server switching
	ProbeTimeoutMs     int  `yaml:"probe_timeout_ms"`
	ProbeConcurrency   int  `yaml:"probe_concurrency"`
	LatencyAutoSwitch  bool `yaml:"latency_auto_switch"`
	LatencyThresholdMs int  `yaml:"latency_threshold_ms"`
	LatencySwitchCount int  `yaml:"latency_switch_count"`
	BlacklistTTLSec    int  `yaml:"blacklist_ttl_sec"`
	WatchdogAutoStart  bool `yaml:"watchdog_auto_start"`

	// Automatic subscription refresh
	SubscriptionRefreshInterval int `yaml:"subscription_refresh_interval"`

	// Local hour at which the panel installs its own updates when that is on
	AutoUpdateHour int `yaml:"auto_update_hour"`

	// Cap on pool size: every node is probed by observatory separately
	PoolMaxNodes int `yaml:"pool_max_nodes"`

	// Health probes of real services, used to catch an exit IP a CDN blocks
	// while plain connectivity still works. One service per round, in rotation.
	HealthCheckURLs     []string `yaml:"health_check_urls"`
	HealthCheckEvery    int      `yaml:"health_check_every"`    // every N watchdog cycles
	HealthFailThreshold int      `yaml:"health_fail_threshold"` // consecutive failures of one service
	HealthQuorum        int      `yaml:"health_quorum"`         // how many services must fail

	// Countries to avoid when switching automatically
	AutoSwitchAvoidCountries []string `yaml:"auto_switch_avoid_countries"`

	// Trust proxy headers (X-Forwarded-For/Host/Proto). Enable ONLY behind a
	// trusted proxy that rewrites them — otherwise they can be spoofed on the
	// direct :3000 socket.
	TrustProxyHeaders bool `yaml:"trust_proxy_headers"`

	// WebAuthn (passkey). Prefer pinning RPID/origins explicitly; deriving them
	// from request headers is allowed only with trust_proxy_headers: true.
	WebAuthnRPID    string   `yaml:"webauthn_rp_id"`
	WebAuthnRPName  string   `yaml:"webauthn_rp_name"`
	WebAuthnOrigins []string `yaml:"webauthn_origins"`

	// Guards the fields the panel changes at runtime
	mu sync.RWMutex
}

// AvoidCountries is the live list of countries automatic switching skips.
func (c *Config) AvoidCountries() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string(nil), c.AutoSwitchAvoidCountries...)
}

// RefreshInterval is the live subscription refresh period; zero turns it off.
func (c *Config) RefreshInterval() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return time.Duration(c.SubscriptionRefreshInterval) * time.Second
}

// SetRuntime replaces the settings the owner edits from the panel.
func (c *Config) SetRuntime(avoid []string, refreshSec int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.AutoSwitchAvoidCountries = append([]string(nil), avoid...)
	c.SubscriptionRefreshInterval = refreshSec
}

// User is the panel account (data/user.json).
type User struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	TOTPSecret   string    `json:"totp_secret"`
	JWTSecret    string    `json:"jwt_secret"`
	CreatedAt    time.Time `json:"created_at"`

	WebAuthnID  []byte                `json:"webauthn_id,omitempty"`
	Credentials []webauthn.Credential `json:"credentials,omitempty"`

	// Hashes of the spare one-time codes for when the authenticator is lost.
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
}

// Server is one entry of the subscription.
type Server struct {
	ID         int    `json:"id"`
	SourceID   string `json:"source_id,omitempty"`
	SourceName string `json:"source_name,omitempty"`
	Name       string `json:"name"`
	// Description is the provider's short note under the name (Happ's
	// serverDescription), shown as a second line when present.
	Description     string          `json:"description,omitempty"`
	Address         string          `json:"address"`
	Port            int             `json:"port"`
	Protocol        string          `json:"protocol"`
	Active          bool            `json:"active"`
	Latency         int             `json:"latency_ms"`
	RawURI          string          `json:"raw_uri,omitempty"`
	RawOutbound     json.RawMessage `json:"raw_outbound,omitempty"`
	RawProfile      json.RawMessage `json:"raw_profile,omitempty"`
	ProfileNodes    int             `json:"profile_nodes,omitempty"`
	GeneratedPool   bool            `json:"-"`
	ProbeKind       string          `json:"probe_kind,omitempty"`
	CheckError      string          `json:"check_error,omitempty"`
	LastChecked     time.Time       `json:"last_checked,omitempty"`
	Country         string          `json:"country,omitempty"`
	CountryOverride string          `json:"country_override,omitempty"`
}

// SubscriptionData is the stored subscription (data/subscription.json).
type SubscriptionData struct {
	CatalogVersion int                  `json:"catalog_version,omitempty"`
	NextServerID   int                  `json:"next_server_id,omitempty"`
	Sources        []SubscriptionSource `json:"sources,omitempty"`
	URL            string               `json:"url"`
	SourceKind     string               `json:"source_kind,omitempty"`
	LastUpdated    time.Time            `json:"last_updated"`
	Servers        []Server             `json:"servers"`
	ActiveID       int                  `json:"active_id"`
}

// URLs and the original node credentials are private router state. API views
// project the source metadata explicitly.
type SubscriptionSource struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Kind        string       `json:"kind"`
	URL         string       `json:"url,omitempty"`
	LastUpdated time.Time    `json:"last_updated"`
	Report      ImportReport `json:"import_report"`
	// Usage is what the provider reported with its last answer.
	Usage *SubscriptionUsage `json:"usage,omitempty"`
}

// SubscriptionUsage is the provider's subscription-userinfo: bytes used and
// allowed, and when the subscription ends (Unix seconds); zero means unknown
// or unlimited.
type SubscriptionUsage struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
	Total    int64 `json:"total"`
	Expire   int64 `json:"expire"`
}

type ImportReport struct {
	Imported           int      `json:"imported"`
	ImportedProfiles   int      `json:"imported_profiles,omitempty"`
	SkippedComposite   int      `json:"skipped_composite"`
	SkippedUnsupported int      `json:"skipped_unsupported"`
	Warnings           []string `json:"warnings,omitempty"`
}

// Status is the connection status reported to the UI.
// RouteProbe describes a check through the selected Mihomo route. Checked is
// false if the local controller could not tell whether traffic got through.
type RouteProbe struct {
	Name, Protocol string
	Latency        int
	Checked        bool
	Selective      bool
	// Pool marks a route through an automatic pool.
	Pool bool
}

type Status struct {
	Connected      bool      `json:"connected"`
	Internet       bool      `json:"internet"`      // the router's own uplink works
	ProxyChecked   bool      `json:"proxy_checked"` // connected was measured through the proxy
	XrayRunning    bool      `json:"xray_running"`
	ProcessUnknown bool      `json:"process_unknown,omitempty"`
	Selective      bool      `json:"selective,omitempty"` // probe targets the VPN route for the blocklist
	Restarting     bool      `json:"restarting"`
	Held           bool      `json:"held,omitempty"` // the internet is paused for devices: a restart under a kill switch
	CurrentServer  string    `json:"current_server"`
	Protocol       string    `json:"protocol"`
	Latency        int       `json:"latency_ms"`
	Uptime         string    `json:"uptime"`
	LastCheck      time.Time `json:"last_check"`
	WatchdogActive bool      `json:"watchdog_active"`
	PanelVersion   string    `json:"panel_version"`

	// XKeen runtime: proxy core (xray/mihomo), proxying mode (TProxy/Hybrid/…),
	// version and layout generation.
	Core         string `json:"core"`
	Mode         string `json:"mode"`
	XKeenVersion string `json:"xkeen_version"`
	Generation   int    `json:"generation"`

	// Searching: the route through an automatic pool failed and the panel is
	// re-checking the pool's servers; the router switches to a working one.
	Searching bool `json:"searching,omitempty"`
	// RoutesDown names the service cards whose own VPN route failed its last check.
	RoutesDown []string `json:"routes_down,omitempty"`
	// Pool marks a default route through an automatic pool.
	Pool bool `json:"pool,omitempty"`
}

// ServiceRouteHealth is one check of a VPN route that one or more service
// cards share.
type ServiceRouteHealth struct {
	Services []string `json:"services"`
	// Pool marks a route through an automatic pool: the router replaces a
	// dead server there by itself.
	Pool    bool `json:"pool"`
	OK      bool `json:"ok"`
	Latency int  `json:"latency_ms"`
}

// SetupRequest starts the initial account setup.
type SetupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// SetupConfirmRequest confirms the TOTP enrolment.
type SetupConfirmRequest struct {
	Code string `json:"code"`
}

// LoginRequest is a login attempt.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
	// Keep this device signed in while the panel is being used.
	Remember bool `json:"remember,omitempty"`
}

// SelectServerRequest selects a server.
type SelectServerRequest struct {
	ID int `json:"id"`
}

// SetCountryRequest overrides a server's country by hand.
type SetCountryRequest struct {
	ID      int    `json:"id"`
	Country string `json:"country"`
}

// UpdateSubscriptionRequest sets the subscription URL.
type UpdateSubscriptionRequest struct {
	URL string `json:"url"`
}
