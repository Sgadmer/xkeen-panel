package api

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"net/http"
	"net/url"
	"strings"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

// HandlePanelAccess returns only the current panel origin. The QR never embeds
// an access key, a session token, subscription data or a router password.
func (h *Handlers) HandlePanelAccess(w http.ResponseWriter, r *http.Request) {
	scheme, host := "http", r.Host
	if r.TLS != nil {
		scheme = "https"
	}
	if h.config.TrustProxyHeaders {
		if r.Header.Get("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		if forwarded := r.Header.Get("X-Forwarded-Host"); forwarded != "" {
			host = forwarded
		}
	}
	origin := scheme + "://" + host
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || len(host) > 255 || strings.ContainsAny(host, " ,\\\r\n\t") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "не удалось определить адрес панели"})
		return
	}
	code, err := qr.Encode(origin+"/", qr.M, qr.Auto)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "не удалось создать QR-код"})
		return
	}
	code, err = barcode.Scale(code, 256, 256)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "не удалось создать QR-код"})
		return
	}
	var image bytes.Buffer
	if png.Encode(&image, code) != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "не удалось создать QR-код"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"url": origin + "/", "qr": "data:image/png;base64," + base64.StdEncoding.EncodeToString(image.Bytes())})
}
