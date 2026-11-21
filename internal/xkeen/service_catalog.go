package xkeen

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"xkeen-panel/internal/geoip"
)

// Specific applications precede their parent categories (Claude before AI,
// YouTube before Google, Prime Video before Amazon).
var serviceCatalog = []struct {
	id, name, geo, suffixes string
}{
	{"claude", "Claude / Anthropic", "anthropic", "anthropic.com claude.ai claude.com claudeusercontent.com claudemcpcontent.com claudeassets.com claude.site anthropicusercontent.com"},
	{"openai", "ChatGPT / OpenAI", "openai", "chatgpt.com openai.com oaistatic.com oaiusercontent.com"},
	{"analytics", "Аналитика и диагностика", "category-telemetry", ""},
	{"youtube", "YouTube", "youtube", "youtube.com youtu.be yt.be youtube-nocookie.com googlevideo.com ytimg.com youtubei.googleapis.com youtube.googleapis.com youtubeembeddedplayer.googleapis.com yt3.googleusercontent.com yt3.ggpht.com youtube-ui.l.google.com wide-youtube.l.google.com youtubekids.com"},
	{"telegram", "Telegram", "telegram", "telegram.org t.me telegram.me tdesktop.com telegram-cdn.org"},
	{"discord", "Discord", "discord", "discord.com discord.gg discordapp.com discordapp.net discord.media"},
	{"spotify", "Spotify", "spotify", "spotify.com scdn.co spotifycdn.com spotifycdn.net"},
	{"github", "GitHub", "github", "github.com github.io githubassets.com githubusercontent.com"},
	{"steam", "Steam", "steam", "steampowered.com steamcommunity.com steamstatic.com steamcontent.com steamserver.net"},
	{"playstation", "PlayStation", "playstation", "playstation.com playstation.net sonyentertainmentnetwork.com"},
	{"xbox", "Xbox", "xbox", "xbox.com xboxlive.com xboxservices.com"},
	{"instagram", "Instagram", "instagram", "instagram.com cdninstagram.com"},
	{"whatsapp", "WhatsApp", "whatsapp", "whatsapp.com whatsapp.net wa.me"},
	{"facebook", "Facebook", "facebook", "facebook.com facebook.net fbcdn.net fb.com messenger.com"},
	{"netflix", "Netflix", "netflix", "netflix.com nflxvideo.net nflximg.net nflxso.net nflxext.com"},
	{"twitch", "Twitch", "twitch", "twitch.tv ttvnw.net jtvnw.net twitchcdn.net"},
	{"disney", "Disney+", "disney", "disneyplus.com disney-plus.net dssott.com disney.com"},
	{"primevideo", "Prime Video", "primevideo", "primevideo.com amazonvideo.com aiv-cdn.net"},
	{"amazon", "Amazon", "amazon", "amazon.com amazon.co.uk amazon.de media-amazon.com"},
	{"twitter", "X (Twitter)", "twitter", "x.com twitter.com twimg.com t.co"},
	{"hulu", "Hulu", "hulu", "hulu.com huluim.com hulustream.com"},
	{"hbo", "HBO", "hbo", "hbo.com hbomax.com max.com"},
	{"line", "LINE", "line", "line.me line-scdn.net line-apps.com"},
	{"google", "Google", "google", "google.com googleapis.com gstatic.com googleusercontent.com"},
	{"ai", "AI", "category-ai-!cn", "perplexity.ai gemini.google.com mistral.ai deepseek.com grok.com character.ai"},
}

// These observed collector hosts are not yet present in category-telemetry.
// Match the exact hosts, never their vendors' websites or whole cloud ranges.
var analyticsHosts = []string{
	"api3.siftscience.com",
	"browser-intake-us5-datadoghq.com",
	"o1158394.ingest.us.sentry.io",
	"http-intake.logs.us5.datadoghq.com",
}

func AnalyticsHosts() []string { return slices.Clone(analyticsHosts) }

func serviceDomains(index int, geosites map[string]bool) []string {
	service := serviceCatalog[index]
	result := []string{}
	for _, domain := range strings.Fields(service.suffixes) {
		result = append(result, "domain:"+domain)
	}
	if service.id == "analytics" {
		for _, host := range analyticsHosts {
			result = append(result, "full:"+host)
		}
	}
	if geosites[service.geo] {
		result = append(result, "ext:geosite_v2fly.dat:"+service.geo)
	}
	return result
}

var cachedServiceGeosites struct {
	sync.Mutex
	path   string
	mtime  time.Time
	size   int64
	groups map[string]bool
}

func serviceGeosites(rt Runtime) map[string]bool {
	path := filepath.Join(filepath.Dir(rt.XrayConfDir), "dat", "geosite_v2fly.dat")
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	c := &cachedServiceGeosites
	c.Lock()
	defer c.Unlock()
	if c.path != path || c.size != info.Size() || !c.mtime.Equal(info.ModTime()) {
		c.groups = geoip.DatCategories(path)
		c.path, c.size, c.mtime = path, info.Size(), info.ModTime()
	}
	return c.groups
}

var serviceDomainNames = func() map[string]string {
	domains := make(map[string]string)
	for _, service := range serviceCatalog {
		for _, suffix := range strings.Fields(service.suffixes) {
			if domains[suffix] == "" {
				domains[suffix] = service.id
			}
		}
	}
	return domains
}()

// ServiceForHost labels diagnostics even when a known site matched a DIRECT rule.
func ServiceForHost(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if slices.Contains(analyticsHosts, host) {
		return "analytics"
	}
	for name := host; name != ""; {
		if id := serviceDomainNames[name]; id != "" {
			return id
		}
		_, rest, _ := strings.Cut(name, ".")
		name = rest
	}
	return customForHost(host)
}

// ServiceSuffixes returns the domains of a service card. Each one stands for
// the domain itself and everything below it.
func ServiceSuffixes(id string) []string {
	for _, service := range serviceCatalog {
		if service.id == id {
			return strings.Fields(service.suffixes)
		}
	}
	var result []string
	if custom, found := customService(id); found {
		for _, domain := range custom.Domains {
			if suffix, ok := strings.CutPrefix(domain, "domain:"); ok {
				result = append(result, suffix)
			}
		}
	}
	return result
}

// ServiceHosts returns the exact host names of a custom card: names that
// belong to it without the names below them.
func ServiceHosts(id string) []string {
	var result []string
	if custom, found := customService(id); found {
		for _, domain := range custom.Domains {
			if host, ok := strings.CutPrefix(domain, "full:"); ok {
				result = append(result, host)
			}
		}
	}
	return result
}

func knownService(id string) bool {
	for _, service := range serviceCatalog {
		if id == service.id {
			return true
		}
	}
	return false
}

// ServiceNames lists the cards in display order without resolving routes or
// loading geodata: the built-in ones, then the owner's.
func ServiceNames() []ServiceName {
	result := make([]ServiceName, 0, len(serviceCatalog))
	for _, service := range serviceCatalog {
		result = append(result, ServiceName{ID: service.id, Name: service.name})
	}
	if current := customServices.Load(); current != nil {
		for _, service := range *current {
			result = append(result, ServiceName{ID: service.ID, Name: service.Name})
		}
	}
	return result
}

type ServiceName struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
