package xkeen

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
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
	// timeout: the provider did not answer in time; worth asking once more.
	timeout bool
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
	return sm.downloadAndParseContext(context.Background(), rawURL)
}

func (sm *SubscriptionManager) downloadAndParseContext(parent context.Context, rawURL string) ([]models.Server, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Hostname() == "" || (parsedURL.Scheme != "https" && parsedURL.Scheme != "http") {
		return nil, fmt.Errorf("нужна корректная HTTP/HTTPS-ссылка подписки")
	}
	state, err := sm.loadSubscriptionClient()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, subscriptionTotalTimeout)
	defer cancel()
	for _, profile := range subscriptionProfilesFor(state, rawURL) {
		servers, err := sm.fetchSubscriptionProfile(ctx, rawURL, state.HWID, profile)
		var slow *subscriptionFetchError
		if err != nil && errors.As(err, &slow) && slow.timeout && ctx.Err() == nil {
			// A busy provider usually answers the second request; the same
			// profile is asked again, never a different one.
			servers, err = sm.fetchSubscriptionProfile(ctx, rawURL, state.HWID, profile)
		}
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
		return &subscriptionRedirectError{"слишком много перенаправлений подписки"}
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return &subscriptionRedirectError{"неподдерживаемое перенаправление подписки"}
	}
	if len(via) > 0 {
		previous := via[len(via)-1]
		if previous.URL.Scheme == "https" && req.URL.Scheme != "https" {
			return &subscriptionRedirectError{"небезопасное перенаправление подписки"}
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
		var timeout net.Error
		slow := errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout()
		return nil, &subscriptionFetchError{message: subscriptionTransportMessage(err), timeout: slow}
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
	usage := ParseSubscriptionUsage(resp.Header.Get("subscription-userinfo"))
	if usage == nil {
		usage = bodySubscriptionUsage(string(body))
	}
	sm.mu.Lock()
	sm.pendingImportReport = cloneSubscriptionImportReport(report)
	sm.pendingUsage = usage
	sm.mu.Unlock()
	return usable, nil
}

// ParseSubscriptionUsage reads "upload=…; download=…; total=…; expire=…".
func ParseSubscriptionUsage(value string) *models.SubscriptionUsage {
	usage := models.SubscriptionUsage{}
	found := false
	for _, part := range strings.Split(value, ";") {
		key, raw, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil || n < 0 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "upload":
			usage.Upload, found = n, true
		case "download":
			usage.Download, found = n, true
		case "total":
			usage.Total, found = n, true
		case "expire":
			usage.Expire, found = n, true
		}
	}
	if !found {
		return nil
	}
	return &usage
}

// Some providers put the same line at the top of the body instead of a header.
func bodySubscriptionUsage(body string) *models.SubscriptionUsage {
	for i, line := range strings.SplitN(body, "\n", 32) {
		if i == 31 {
			break
		}
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
		if key, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(key), "subscription-userinfo") {
			return ParseSubscriptionUsage(value)
		}
	}
	return nil
}

// url.Error includes the full secret URL. Name the kind of failure with fixed
// text only; never wrap the error or pass upstream bodies to logs or the
// browser. A dead address is the usual sign that the provider moved its
// subscription server, so say what the owner can do about it.
func subscriptionTransportMessage(err error) string {
	const prefix = "не удалось загрузить подписку: "
	const stale = ". Возможно, ссылка устарела: получите у провайдера новую"
	var redirect *subscriptionRedirectError
	var dns *net.DNSError
	var timeout net.Error
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var verification *tls.CertificateVerificationError
	switch {
	case errors.As(err, &redirect):
		return prefix + redirect.Error()
	case errors.As(err, &dns) && dns.IsNotFound:
		return prefix + "адрес сервера подписки не найден" + stale
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &timeout) && timeout.Timeout():
		// A slow answer is the provider's load, not a moved address.
		return prefix + "сервер подписки не ответил вовремя, панель повторит позже"
	case errors.As(err, &authority), errors.As(err, &hostname), errors.As(err, &invalid), errors.As(err, &verification):
		return prefix + "сервер подписки предъявил недействительный TLS-сертификат"
	}
	return prefix + "ошибка сети, TLS или перенаправления"
}

type subscriptionRedirectError struct{ message string }

func (err *subscriptionRedirectError) Error() string { return err.message }

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
