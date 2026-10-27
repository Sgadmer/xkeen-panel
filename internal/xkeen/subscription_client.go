package xkeen

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// This file is separate from subscription.json so an unsuccessful first import
// still reuses the same registered device on the next attempt. Installations
// migrating an existing device can preseed version + hwid before any fetch.
type subscriptionClientState struct {
	Version   int    `json:"version"`
	HWID      string `json:"hwid"`
	Profile   string `json:"profile,omitempty"`
	URLSHA256 string `json:"url_sha256,omitempty"`
}

var subscriptionClientFileMu sync.Mutex
var subscriptionHWIDPattern = regexp.MustCompile(`^[a-zA-Z0-9=-]{10,64}$`)

func (sm *SubscriptionManager) subscriptionClientPath() string {
	return filepath.Join(sm.dataDir, "subscription-client.json")
}

func subscriptionURLHash(rawURL string) string {
	sum := sha256.Sum256([]byte(rawURL))
	return hex.EncodeToString(sum[:])
}

func subscriptionClientError() error {
	return fmt.Errorf("не удалось прочитать или сохранить идентификатор устройства; автоматическая смена HWID не выполнялась")
}

func (sm *SubscriptionManager) loadSubscriptionClient() (subscriptionClientState, error) {
	subscriptionClientFileMu.Lock()
	defer subscriptionClientFileMu.Unlock()
	return sm.loadSubscriptionClientLocked()
}

func (sm *SubscriptionManager) loadSubscriptionClientLocked() (subscriptionClientState, error) {
	var state subscriptionClientState
	path := sm.subscriptionClientPath()
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Size() > 8192 {
			return state, subscriptionClientError()
		}
		data, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(data, &state) != nil || state.Version != 1 || !subscriptionHWIDPattern.MatchString(state.HWID) {
			return subscriptionClientState{}, subscriptionClientError()
		}
		// Never silently generate a replacement when a stored identity is bad.
		if err := os.Chmod(path, 0600); err != nil {
			return subscriptionClientState{}, subscriptionClientError()
		}
		return state, nil
	}
	if !os.IsNotExist(err) {
		return state, subscriptionClientError()
	}
	if err := os.MkdirAll(sm.dataDir, 0700); err != nil {
		return state, subscriptionClientError()
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return state, subscriptionClientError()
	}
	random[6] = random[6]&0x0f | 0x40
	random[8] = random[8]&0x3f | 0x80
	id := hex.EncodeToString(random[:])
	state = subscriptionClientState{
		Version: 1,
		HWID:    strings.Join([]string{id[:8], id[8:12], id[12:16], id[16:20], id[20:]}, "-"),
	}
	if err := sm.saveSubscriptionClientLocked(state); err != nil {
		return subscriptionClientState{}, err
	}
	return state, nil
}

func (sm *SubscriptionManager) saveSubscriptionClientLocked(state subscriptionClientState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return subscriptionClientError()
	}
	if err := writeFileAtomic(sm.subscriptionClientPath(), append(data, '\n'), 0600); err != nil {
		return subscriptionClientError()
	}
	return nil
}

func (sm *SubscriptionManager) rememberSubscriptionProfile(rawURL, hwid, profile string) error {
	subscriptionClientFileMu.Lock()
	defer subscriptionClientFileMu.Unlock()
	state, err := sm.loadSubscriptionClientLocked()
	if err != nil {
		return err
	}
	if state.HWID != hwid {
		return subscriptionClientError()
	}
	state.Profile = profile
	state.URLSHA256 = subscriptionURLHash(rawURL)
	return sm.saveSubscriptionClientLocked(state)
}
