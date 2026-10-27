package xkeen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"xkeen-panel/internal/models"
)

const subscriptionBodyLimit = 2 << 20
const subscriptionTotalTimeout = 45 * time.Second
const subscriptionAttemptTimeout = 15 * time.Second

type subscriptionProfile struct {
	name      string
	userAgent string
}

var subscriptionProfiles = []subscriptionProfile{
	{name: "incy", userAgent: "INCY/1.0/Linux"},
	{name: "go", userAgent: "Go-http-client/1.1"},
	{name: "happ", userAgent: "Happ/3.26.1"},
	// Format negotiation changes only the client label, never the URL or HWID.
	// Providers commonly select their URI, Mihomo or sing-box serializers by UA.
	{name: "v2ray", userAgent: "v2rayN"},
	{name: "mihomo", userAgent: "mihomo"},
	{name: "clash", userAgent: "clash.meta"},
	{name: "sing-box", userAgent: "sing-box"},
}

type subscriptionFetchError struct {
	message string
	retry   bool
}

func (err *subscriptionFetchError) Error() string { return err.message }

func subscriptionProfilesFor(state subscriptionClientState, rawURL string) []subscriptionProfile {
	profiles := make([]subscriptionProfile, 0, len(subscriptionProfiles))
	if state.URLSHA256 == subscriptionURLHash(rawURL) {
		for _, profile := range subscriptionProfiles {
			if state.Profile == profile.name {
				profiles = append(profiles, profile)
			}
		}
	}
	for _, profile := range subscriptionProfiles {
		if len(profiles) == 0 || profile.name != profiles[0].name {
			profiles = append(profiles, profile)
		}
	}
	return profiles
}

func (sm *SubscriptionManager) downloadAndParse(rawURL string) ([]models.Server, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Hostname() == "" || (parsedURL.Scheme != "https" && parsedURL.Scheme != "http") {
		return nil, fmt.Errorf("нужна корректная HTTP/HTTPS-ссылка подписки")
	}
	state, err := sm.loadSubscriptionClient()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), subscriptionTotalTimeout)
	defer cancel()
	for _, profile := range subscriptionProfilesFor(state, rawURL) {
		servers, err := sm.fetchSubscriptionProfile(ctx, rawURL, state.HWID, profile)
		if err == nil {
			if err := sm.rememberSubscriptionProfile(rawURL, state.HWID, profile.name); err != nil {
				return nil, err
			}
			return servers, nil
		}
		var fetchError *subscriptionFetchError
		if !errors.As(err, &fetchError) || !fetchError.retry || ctx.Err() != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("сервис не выдал поддерживаемые серверы; проверьте формат подписки и разрешённые приложения")
}

func subscriptionRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) > 5 {
		return fmt.Errorf("слишком много перенаправлений подписки")
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return fmt.Errorf("неподдерживаемое перенаправление подписки")
	}
	if len(via) > 0 {
		previous := via[len(via)-1]
		if previous.URL.Scheme == "https" && req.URL.Scheme != "https" {
			return fmt.Errorf("небезопасное перенаправление подписки")
		}
		// net/http normally forwards custom headers and builds Referer from
		// the previous secret URL. Neither device identity nor that URL may
		// escape to another authority in a redirect chain.
		req.Header.Del("Referer")
		if !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
			for _, name := range []string{"x-hwid", "X-Device-ID", "x-device-os", "x-ver-os", "x-device-model", "x-client", "Authorization", "Cookie"} {
				req.Header.Del(name)
			}
		}
	}
	return nil
}

func (sm *SubscriptionManager) fetchSubscriptionProfile(ctx context.Context, rawURL, hwid string, profile subscriptionProfile) ([]models.Server, error) {
	client := http.Client{Timeout: subscriptionAttemptTimeout}
	if sm.httpClient != nil {
		client = *sm.httpClient
		if client.Timeout <= 0 || client.Timeout > subscriptionAttemptTimeout {
			client.Timeout = subscriptionAttemptTimeout
		}
	}
	client.CheckRedirect = subscriptionRedirectPolicy
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, &subscriptionFetchError{message: "не удалось подготовить запрос подписки"}
	}
	req.Header.Set("User-Agent", profile.userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("x-hwid", hwid)
	resp, err := client.Do(req)
	if err != nil {
		// url.Error includes the full secret URL. Do not wrap it or pass
		// upstream error bodies into logs or the browser.
		return nil, &subscriptionFetchError{message: "не удалось загрузить подписку: ошибка сети, TLS или перенаправления"}
	}
	defer resp.Body.Close()
	if subscriptionTrueHeader(resp.Header, "x-hwid-max-devices-reached") || subscriptionTrueHeader(resp.Header, "x-hwid-limit") {
		return nil, &subscriptionFetchError{message: "достигнут лимит устройств подписки; HWID роутера сохранён без изменения"}
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, &subscriptionFetchError{message: "сервис временно ограничил частоту запросов подписки"}
	}
	if resp.StatusCode >= http.StatusInternalServerError {
		return nil, &subscriptionFetchError{message: fmt.Sprintf("сервис подписки вернул HTTP %d", resp.StatusCode)}
	}
	// Authentication/payment/expiry failures take precedence over compatibility
	// headers: trying another label must never repeat a terminal request.
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusForbidden, http.StatusProxyAuthRequired, http.StatusGone:
		return nil, &subscriptionFetchError{message: fmt.Sprintf("сервис подписки вернул HTTP %d", resp.StatusCode)}
	}
	if resp.ContentLength > subscriptionBodyLimit {
		return nil, &subscriptionFetchError{message: "ответ подписки превышает допустимые 2 МиБ"}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, subscriptionBodyLimit+1))
	if err != nil {
		return nil, &subscriptionFetchError{message: "не удалось прочитать ответ подписки"}
	}
	if len(body) > subscriptionBodyLimit {
		return nil, &subscriptionFetchError{message: "ответ подписки превышает допустимые 2 МиБ"}
	}
	if providerTerminalText(string(body)) {
		return nil, &subscriptionFetchError{message: "сервис сообщил об истечении подписки или лимите устройств"}
	}
	if providerRateLimitText(string(body)) {
		return nil, &subscriptionFetchError{message: "сервис временно ограничил частоту запросов подписки"}
	}
	if subscriptionTrueHeader(resp.Header, "x-hwid-not-supported") {
		return nil, &subscriptionFetchError{message: "сервис не принял профиль приложения", retry: true}
	}
	if resp.StatusCode != http.StatusOK {
		// Only explicit compatibility failures justify trying a different
		// client profile. A 404 or 403 alone is not a HWID diagnosis.
		if providerCompatibilityText(string(body)) {
			return nil, &subscriptionFetchError{message: "сервис требует другой профиль приложения", retry: true}
		}
		return nil, &subscriptionFetchError{message: fmt.Sprintf("сервис подписки вернул HTTP %d", resp.StatusCode)}
	}
	servers, report, parseError := ParseSubscriptionDetailed(string(body))
	if parseError != nil {
		if providerTerminalText(string(body)) {
			return nil, &subscriptionFetchError{message: "сервис сообщил об истечении подписки или лимите устройств"}
		}
		return nil, &subscriptionFetchError{message: "сервис вернул неподдерживаемый формат подписки", retry: true}
	}
	usable := make([]models.Server, 0, len(servers))
	hasTerminal := false
	for _, server := range servers {
		if providerTerminalText(server.Name) {
			hasTerminal = true
			continue
		}
		if providerCompatibilityText(server.Name) {
			continue
		}
		server.ID = len(usable)
		usable = append(usable, server)
	}
	if len(usable) == 0 {
		if hasTerminal {
			return nil, &subscriptionFetchError{message: "сервис сообщил об истечении подписки или лимите устройств"}
		}
		return nil, &subscriptionFetchError{message: "сервис вернул сообщение вместо серверов", retry: true}
	}
	if len(usable) < len(servers) {
		report.SkippedUnsupported += len(servers) - len(usable)
		report.Warnings = append(report.Warnings, "Служебные сообщения провайдера исключены из списка серверов.")
	}
	report.Imported = len(usable)
	sm.mu.Lock()
	sm.pendingImportReport = cloneSubscriptionImportReport(report)
	sm.mu.Unlock()
	return usable, nil
}

func subscriptionTrueHeader(headers http.Header, name string) bool {
	switch strings.ToLower(strings.TrimSpace(headers.Get(name))) {
	case "true", "1", "yes":
		return true
	}
	return false
}

func providerCompatibilityText(text string) bool {
	text = strings.ToLower(text)
	for _, phrase := range []string{
		"приложение не поддерживается", "приложение не поддреживается", "приложение не поддрежвается",
		"используйте incy", "включите hwid", "unsupported application", "unsupported client",
	} {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}

func providerTerminalText(text string) bool {
	text = strings.ToLower(text)
	for _, phrase := range []string{
		"достигнут лимит устройств", "превышен лимит устройств", "device limit reached",
		"подписка истекла", "подписка закончилась", "срок подписки истёк", "subscription expired",
	} {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}

func providerRateLimitText(text string) bool {
	text = strings.ToLower(text)
	for _, phrase := range []string{"too many requests", "rate limit exceeded", "слишком много запросов", "превышен лимит запросов"} {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}
