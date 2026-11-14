package api

import (
	"net/http"
	"xkeen-panel/installer"
)

func (h *Handlers) HandleClaudeFirewallStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, installer.ClaudeFirewallStatus(r.Context()))
}

func (h *Handlers) HandleInstallClaudeFirewall(w http.ResponseWriter, r *http.Request) {
	h.watchdog.LockChanges()
	defer h.watchdog.UnlockChanges()
	if h.Cards != nil {
		policy, err := h.Cards.KillSwitch()
		if err != nil || !policy.Protects("claude") {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "Для установки фильтра включите Kill switch для Claude."})
			return
		}
	}
	status, err := installer.InstallClaudeFirewall(r.Context())
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, status)
}
