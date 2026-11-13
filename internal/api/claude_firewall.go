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
	status, err := installer.InstallClaudeFirewall(r.Context())
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, status)
}
