// Package installer bundles the optional, narrowly scoped Anthropic firewall
// companion with the panel. No downloaded or user-supplied commands are run.
package installer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

//go:embed strict-guard.sh S01xkeen-panel-guard 99-xkeen-panel-guard.sh install-claude-guard.sh
var guardScripts embed.FS

var companions = map[string]string{
	"strict-guard.sh":         "/opt/sbin/xkeen-panel-guard",
	"S01xkeen-panel-guard":    "/opt/etc/init.d/S01xkeen-panel-guard",
	"99-xkeen-panel-guard.sh": "/opt/etc/ndm/netfilter.d/99-xkeen-panel-guard.sh",
}

var firewallEnv = []string{"PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}

type ClaudeFirewall struct {
	Available bool `json:"available"`
	Installed bool `json:"installed"`
	Ready     bool `json:"ready"`
}

// Compare all installed executable files with the assets compiled into this
// binary before invoking the companion or reporting its software filter state.
func ClaudeFirewallStatus(ctx context.Context) ClaudeFirewall {
	status := ClaudeFirewall{Available: runtime.GOOS == "linux"}
	if !status.Available {
		return status
	}
	for name, path := range companions {
		asset, err := guardScripts.ReadFile(name)
		if err != nil {
			return status
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Size() > 64<<10 {
			return status
		}
		raw, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(raw, asset) && !legacyGuard(name, raw) {
			return status
		}
	}
	status.Installed = true
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, companions["strict-guard.sh"], "check-api")
	cmd.Env = firewallEnv
	status.Ready = cmd.Run() == nil
	return status
}

// This is the exact LF-encoded script embedded in earlier panel releases.
func legacyGuard(name string, raw []byte) bool {
	return name == "strict-guard.sh" && fmt.Sprintf("%x", sha256.Sum256(raw)) == "e992747abdeccd061c9fa0a424aa69558c29e6f89941154f565dad95b773e564"
}

func upgradeLegacyGuard() error {
	path := companions["strict-guard.sh"]
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !legacyGuard("strict-guard.sh", raw) {
		return nil
	}
	asset, err := guardScripts.ReadFile("strict-guard.sh")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".xkp-guard-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(asset); err == nil {
		err = tmp.Chmod(0755)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("изменился файл фильтра Anthropic")
	}
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, current) {
		return errors.New("изменился файл фильтра Anthropic")
	}
	return os.Rename(tmp.Name(), path)
}

func SetInstalledClaudeFirewall(ctx context.Context, enabled bool) error {
	status := ClaudeFirewallStatus(ctx)
	if !status.Installed {
		if status.Available {
			if _, err := os.Lstat(companions["strict-guard.sh"]); !os.IsNotExist(err) {
				return errors.New("версия установленного фильтра Anthropic не распознана")
			}
		}
		return nil
	}
	if err := upgradeLegacyGuard(); err != nil {
		return err
	}
	mode := "suspend-api"
	if enabled {
		mode = "resume-api"
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, companions["strict-guard.sh"], mode)
	cmd.Env = firewallEnv
	if cmd.Run() != nil {
		return errors.New("не удалось изменить фильтр адресов Anthropic")
	}
	return nil
}

func ClaudeFirewallNeedsSync(enabled bool) bool {
	if _, err := os.Lstat(companions["strict-guard.sh"]); err != nil {
		return false
	}
	if _, err := os.Lstat("/opt/etc/xkeen-panel-guard-api.pending"); err == nil {
		return true
	}
	_, err := os.Stat("/opt/etc/xkeen-panel-guard-api.disabled")
	return enabled && err == nil || !enabled && os.IsNotExist(err)
}

func InstallClaudeFirewall(ctx context.Context) (ClaudeFirewall, error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return ClaudeFirewall{}, errors.New("для включения фильтра требуется процесс панели на роутере с правами root")
	}
	if err := upgradeLegacyGuard(); err != nil {
		return ClaudeFirewall{}, err
	}
	dir, err := os.MkdirTemp("", "xkeen-panel-guard-")
	if err != nil {
		return ClaudeFirewall{}, err
	}
	defer os.RemoveAll(dir)
	entries, err := guardScripts.ReadDir(".")
	if err != nil {
		return ClaudeFirewall{}, err
	}
	for _, entry := range entries {
		raw, err := guardScripts.ReadFile(entry.Name())
		if err != nil {
			return ClaudeFirewall{}, err
		}
		if err := os.WriteFile(filepath.Join(dir, entry.Name()), raw, 0600); err != nil {
			return ClaudeFirewall{}, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", filepath.Join(dir, "install-claude-guard.sh"), "install")
	cmd.Env = firewallEnv
	if err := cmd.Run(); err != nil {
		return ClaudeFirewall{}, errors.New("не удалось установить или проверить фильтр Anthropic API. Проверьте доступность iptables и ip6tables, xtables-restore и наличие других версий этих файлов")
	}
	status := ClaudeFirewallStatus(ctx)
	if !status.Ready {
		return status, errors.New("проверка правил IPv4 и IPv6 после установки не прошла")
	}
	return status, nil
}
