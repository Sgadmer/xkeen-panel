// Package installer bundles the optional, narrowly scoped Anthropic firewall
// companion with the panel. No downloaded or user-supplied commands are run.
package installer

import (
	"bytes"
	"context"
	"embed"
	"errors"
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
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Size() != int64(len(asset)) {
			return status
		}
		raw, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(raw, asset) {
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

func InstallClaudeFirewall(ctx context.Context) (ClaudeFirewall, error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return ClaudeFirewall{}, errors.New("для включения фильтра требуется процесс панели на роутере с правами root")
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
