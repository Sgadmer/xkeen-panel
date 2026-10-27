package xkeen

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestSubscriptionFormatProfilesReuseHWIDURLAndRememberSuccess(t *testing.T) {
	for _, wanted := range []string{"v2ray", "mihomo", "clash", "sing-box"} {
		t.Run(wanted, func(t *testing.T) {
			sm := NewSubscriptionManager(t.TempDir())
			var target subscriptionProfile
			for _, profile := range subscriptionProfiles {
				if profile.name == wanted {
					target = profile
				}
			}
			if target.name == "" {
				t.Fatal("missing format profile")
			}
			var seen []subscriptionSeenRequest
			var paths []string
			var mu sync.Mutex
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				seen = append(seen, subscriptionSeenRequest{r.Header.Get("x-hwid"), r.UserAgent()})
				paths = append(paths, r.URL.RequestURI())
				mu.Unlock()
				if r.UserAgent() != target.userAgent {
					fmt.Fprint(w, "unsupported application")
					return
				}
				fmt.Fprint(w, uriA)
			}))
			defer srv.Close()
			rawURL := srv.URL + "/private-token?signature=keep%2Bencoded&target=custom"
			if _, err := sm.UpdateURL(rawURL); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			firstCount := len(seen)
			mu.Unlock()
			if _, err := sm.Refresh(); err != nil {
				t.Fatal(err)
			}
			state := readTestSubscriptionClient(t, sm)
			mu.Lock()
			defer mu.Unlock()
			if len(seen) != firstCount+1 || seen[len(seen)-1].UA != target.userAgent || state.Profile != wanted {
				t.Fatal("successful format profile was not remembered")
			}
			for index, request := range seen {
				if request.HWID != state.HWID || request.HWID == "" || paths[index] != "/private-token?signature=keep%2Bencoded&target=custom" {
					t.Fatal("fallback registered another identity or changed the signed subscription URL")
				}
			}
		})
	}
}

func TestSubscriptionTerminalResponseOverridesCompatibilityHints(t *testing.T) {
	for _, status := range []int{401, 402, 403, 407, 410, 429, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("x-hwid-not-supported", "true")
				w.WriteHeader(status)
				fmt.Fprint(w, "unsupported application private-token")
			}))
			defer srv.Close()
			_, err := NewSubscriptionManager(t.TempDir()).UpdateURL(srv.URL + "/private-token")
			if err == nil || strings.Contains(err.Error(), "private-token") || requests.Load() != 1 {
				t.Fatal("terminal response retried or leaked body/URL")
			}
		})
	}
	for _, body := range []string{"subscription expired; unsupported application", "too many requests; unsupported application", "достигнут лимит устройств; используйте incy"} {
		var requests atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			w.Header().Set("x-hwid-not-supported", "true")
			fmt.Fprint(w, body)
		}))
		_, err := NewSubscriptionManager(t.TempDir()).UpdateURL(srv.URL)
		srv.Close()
		if err == nil || requests.Load() != 1 {
			t.Fatal("terminal/rate-limit body was retried as compatibility failure")
		}
	}
}
