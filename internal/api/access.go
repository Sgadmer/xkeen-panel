package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

func addressQR(address string) (string, error) {
	code, err := qr.Encode(address, qr.M, qr.Auto)
	if err != nil {
		return "", err
	}
	code, err = barcode.Scale(code, 256, 256)
	if err != nil {
		return "", err
	}
	var image bytes.Buffer
	if err := png.Encode(&image, code); err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(image.Bytes()), nil
}

func (h *Handlers) accessOrigin(r *http.Request) (string, error) {
	if h.FaceID != nil {
		// The HTTP address shown in a QR code must not come from client headers.
		return "http://" + h.FaceID.listen + "/", nil
	}
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
		return "", fmt.Errorf("не удалось определить адрес панели")
	}
	return origin + "/", nil
}

func (h *Handlers) HandlePanelAccess(w http.ResponseWriter, r *http.Request) {
	address, err := h.accessOrigin(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	code, err := addressQR(address)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "не удалось создать QR-код"})
		return
	}
	state := faceIDView{Status: "unconfigured"}
	external := hasExplicitWebAuthn(h.config)
	if external {
		state.Status = "external"
	} else if h.FaceID != nil {
		state = h.FaceID.status(r.Context())
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"url": address, "qr": code, "face_id": state,
		"passkey_domain_configured": external || state.Status == "ready",
	})
}

func (h *Handlers) HandlePrepareFaceID(w http.ResponseWriter, r *http.Request) {
	if h.FaceID == nil || hasExplicitWebAuthn(h.config) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "Автонастройка доступна на домашнем адресе панели с ненастроенным HTTPS-входом."})
		return
	}
	var in struct {
		Label       string `json:"label"`
		AdminAccess string `json:"admin_access,omitempty"`
		ExpectedURL string `json:"expected_url"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil || dec.Decode(&struct{}{}) != io.EOF || !domainLabel.MatchString(in.Label) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Введите имя из строчных латинских букв, цифр и дефисов, до 63 символов."})
		return
	}
	if in.AdminAccess != "" && in.AdminAccess != "private" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Для настройки поддерживается только доступ из домашней сети."})
		return
	}
	expected, err := parsePanelOrigin(in.ExpectedURL)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Сначала откройте предварительный просмотр HTTPS-адреса."})
		return
	}
	if err := h.FaceID.configure(r.Context(), in.Label, in.AdminAccess, expected.String()); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	h.HandlePanelAccess(w, r)
}

func (h *Handlers) HandlePlanFaceID(w http.ResponseWriter, r *http.Request) {
	if h.FaceID == nil || hasExplicitWebAuthn(h.config) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "Автонастройка адреса для этой панели недоступна."})
		return
	}
	label := r.URL.Query().Get("label")
	if !domainLabel.MatchString(label) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Некорректное имя домена."})
		return
	}
	raw, public, err := h.FaceID.plan(r.Context(), label)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	u, err := parsePanelOrigin(raw)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"https_url": u.String() + "/", "router_admin_public": public})
}
