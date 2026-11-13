package xkeen

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
	"xkeen-panel/internal/models"
)

// CardProxy is a Mihomo VLESS/TLS endpoint on 127.0.0.1. Both TCP and UDP
// travel inside the authenticated stream. The key never leaves the worker.
type CardProxy struct {
	Port        int
	UUID        string
	ServerName  string
	Fingerprint string
}

func cardTransportTemplate(path string) (map[string]interface{}, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать маршрут для исходящего VPN")
	}
	var cfg struct {
		Mark uint32 `yaml:"routing-mark"`
	}
	if yaml.Unmarshal(data, &cfg) != nil {
		return nil, fmt.Errorf("неверная исходящая метка Mihomo")
	}
	// Use the mark of the existing VPN transport on the provider-facing socket.
	// DNS never acquires a direct transport from this template.
	return map[string]interface{}{"streamSettings": map[string]interface{}{"sockopt": map[string]interface{}{"mark": cfg.Mark}}}, nil
}

func cardWorkerRuntime(rt Runtime) (Runtime, error) {
	if !filepath.IsAbs(rt.XrayConfDir) || !filepath.IsAbs(rt.CoreBin) {
		return Runtime{}, fmt.Errorf("не обнаружено рабочее окружение Xray для карточек")
	}
	if rt.Core == CoreMihomo {
		name := "xray"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		rt.CoreBin = filepath.Join(filepath.Dir(rt.CoreBin), name)
	}
	rt.Core = CoreXray
	root := filepath.Join(filepath.Dir(rt.XrayConfDir), "xkeen-panel-cards")
	if err := privateWorkerDir(root); err != nil {
		return Runtime{}, err
	}
	dat := filepath.Join(root, "dat")
	target := filepath.Join(filepath.Dir(rt.XrayConfDir), "dat")
	if runtime.GOOS == "linux" {
		if err := os.Symlink(target, dat); err != nil && !os.IsExist(err) {
			return Runtime{}, err
		}
		dst, err := os.Readlink(dat)
		if err != nil || dst != target {
			return Runtime{}, fmt.Errorf("ошибка каталога геоданных карточек")
		}
	}
	rt.XrayConfDir = filepath.Join(root, "configs")
	return rt, nil
}

// PrepareCardProxy preserves the complete provider policy for aggregate
// targets. A standalone endpoint is the only tunnel in its isolated profile.
func PrepareCardProxy(rt Runtime, id string, server models.Server) (CardProxy, error) {
	if id == "" || ServiceTargetID(server) != id {
		return CardProxy{}, fmt.Errorf("не совпадает идентификатор цели карточки")
	}
	if len(server.RawProfile) == 0 {
		tunnel, err := BuildServerOutbound(server, "selected", nil)
		if err != nil || !permittedServiceOutbound(tunnel) {
			return CardProxy{}, fmt.Errorf("цель карточки не является одиночным VPN-сервером")
		}
		raw, err := json.Marshal(map[string]interface{}{"outbounds": []interface{}{tunnel}})
		if err != nil {
			return CardProxy{}, profileError()
		}
		server = models.Server{Protocol: "xray-profile", RawProfile: raw}
	}
	worker, err := cardWorkerRuntime(rt)
	if err != nil {
		return CardProxy{}, err
	}
	template, err := cardTransportTemplate(rt.MihomoConf)
	if err != nil {
		return CardProxy{}, err
	}
	key, err := prepareProfileWorker(worker, id, server, template)
	if err != nil {
		return CardProxy{}, err
	}
	block, _ := pem.Decode([]byte(key.Cert))
	if block == nil {
		return CardProxy{}, profileError()
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CardProxy{}, err
	}
	digest := sha256.Sum256(cert.Raw)
	return CardProxy{Port: key.Port, UUID: key.User, ServerName: workerHostname, Fingerprint: hex.EncodeToString(digest[:])}, nil
}

// PruneCardProxies is independent of the custom panel's native Xray routes.
// Only call after the complete set of Mihomo selections has been committed.
func PruneCardProxies(rt Runtime, keep map[string]bool) error {
	worker, err := cardWorkerRuntime(rt)
	if err != nil {
		return err
	}
	return PruneServiceProfiles(worker, keep)
}
