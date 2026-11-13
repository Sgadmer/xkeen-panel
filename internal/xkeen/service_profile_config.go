package xkeen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"xkeen-panel/internal/models"
)

const workerInput = "protected-service-input"
const workerDNS = "protected-service-dns"
const workerBlock = "protected-service-block"
const workerHostname = "xkeen-worker.invalid"

type serviceWorkerKey struct {
	Port int
	User string
	Cert string
	Key  string
}

func newServiceWorkerKey(port int) (serviceWorkerKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return serviceWorkerKey{}, err
	}
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return serviceWorkerKey{}, err
	}
	// Serial numbers are public in the TLS certificate. Generate the VLESS
	// account separately so it cannot be reconstructed from a handshake.
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return serviceWorkerKey{}, err
	}
	serial.Add(serial, big.NewInt(1))
	entropy[6] = entropy[6]&0x0f | 0x40
	entropy[8] = entropy[8]&0x3f | 0x80
	id := hex.EncodeToString(entropy[:])
	cert := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: workerHostname}, DNSNames: []string{workerHostname},
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().AddDate(15, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		return serviceWorkerKey{}, err
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return serviceWorkerKey{}, err
	}
	return serviceWorkerKey{Port: port, User: id[:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:],
		Cert: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		Key:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private})),
	}, nil
}

// The main core authenticates the worker before passing any target address or
// datagram. If some other process later binds this port, TLS validation fails.
func (key serviceWorkerKey) outbound(tag string) map[string]interface{} {
	return map[string]interface{}{
		"tag": tag, "protocol": "vless",
		"settings": map[string]interface{}{"address": "127.0.0.1", "port": key.Port, "id": key.User, "encryption": "none"},
		"streamSettings": map[string]interface{}{"network": "tcp", "security": "tls", "tlsSettings": map[string]interface{}{
			"serverName": workerHostname, "disableSystemRoot": true, "certificates": []interface{}{map[string]interface{}{"usage": "verify", "certificate": pemLines(key.Cert)}},
		}},
	}
}

func pemLines(value string) []string { return strings.Split(strings.TrimSpace(value), "\n") }

func serviceWorkerConfig(server models.Server, template map[string]interface{}, key serviceWorkerKey) (map[string]interface{}, error) {
	bundle, err := BuildProfileBundle(server, "worker", template)
	if err != nil {
		return nil, err
	}
	binding, err := BindProfileRules(bundle, []string{workerInput})
	if err != nil {
		return nil, err
	}
	in := map[string]interface{}{
		"tag": workerInput, "listen": "127.0.0.1", "port": key.Port, "protocol": "vless",
		"settings": map[string]interface{}{"clients": []interface{}{map[string]interface{}{"id": key.User}}, "decryption": "none"},
		"streamSettings": map[string]interface{}{"network": "tcp", "security": "tls", "tlsSettings": map[string]interface{}{
			"certificates": []interface{}{map[string]interface{}{"certificate": pemLines(key.Cert), "key": pemLines(key.Key)}},
		}},
	}
	if len(bundle.Sniffing) > 0 {
		in["sniffing"] = bundle.Sniffing
	}
	outbounds := []interface{}{map[string]interface{}{"tag": workerBlock, "protocol": "blackhole"}}
	tunnels := map[string]bool{}
	for _, raw := range bundle.InternalOutbounds {
		out := mapOf(raw)
		proto, _ := out["protocol"].(string)
		tag := out["tag"].(string)
		switch proto {
		case "direct", "freedom", "blackhole", "block":
			out = map[string]interface{}{"tag": tag, "protocol": "blackhole"}
		case "dns":
			// Redirecting non-IP queries through an arbitrary server from the
			// subscription can bypass the built-in resolver.
			out = map[string]interface{}{"tag": tag, "protocol": "dns", "settings": map[string]interface{}{"nonIPQuery": "drop"}}
		case "vless", "vmess", "trojan", "shadowsocks", "socks", "http", "hysteria":
			tunnels[tag] = true
			// Preserve the original destination hostname to the proxy. Routing
			// IP predicates use only the protected built-in resolver below.
			out["targetStrategy"] = "AsIs"
		case "loopback":
		default:
			return nil, fmt.Errorf("протокол составного профиля не поддерживает защищённый режим")
		}
		outbounds = append(outbounds, out)
	}
	if len(tunnels) == 0 {
		return nil, fmt.Errorf("в составном профиле нет поддерживаемого VPN-выхода")
	}
	outbounds = append(outbounds, binding.GuardOutbounds...)
	// Use the provider's catch-all choice for resolver traffic. A direct or
	// ambiguous default blocks DNS. A numeric resolver address avoids bootstrap.
	dnsRule := map[string]interface{}{"type": "field", "inboundTag": []string{workerDNS}, "outboundTag": workerBlock}
	for _, raw := range binding.ClientRules {
		rule := mapOf(raw)
		if !profileCatchAll(rule) {
			continue
		}
		if bal, ok := rule["balancerTag"].(string); ok {
			delete(dnsRule, "outboundTag")
			dnsRule["balancerTag"] = bal
		} else if tag, ok := rule["outboundTag"].(string); ok && tunnels[tag] {
			dnsRule["outboundTag"] = tag
		}
		break
	}
	for _, raw := range bundle.Balancers {
		bal := mapOf(raw)
		if _, ok := bal["fallbackTag"]; !ok {
			bal["fallbackTag"] = workerBlock
		}
	}
	rules := append([]interface{}{dnsRule}, binding.OwnedRules...)
	rules = append(rules, binding.ClientRules...)
	routing := map[string]interface{}{"rules": rules, "balancers": bundle.Balancers}
	for k, v := range bundle.RoutingGlobals {
		if v != nil {
			routing[k] = v
		}
	}
	config := map[string]interface{}{"log": map[string]interface{}{"loglevel": "none"}, "inbounds": []interface{}{in}, "outbounds": outbounds, "routing": routing,
		"dns": map[string]interface{}{"tag": workerDNS, "servers": []string{"https://1.1.1.1/dns-query"}, "disableFallback": true, "useSystemHosts": false},
	}
	for _, k := range []string{"policy", "observatory", "burstObservatory"} {
		if v := bundle.Globals[k]; v != nil {
			config[k] = v
		}
	}
	// Burst's optional connectivity check explicitly uses Go's direct HTTP
	// client. Its per-member probes use the tagged proxy and remain enabled.
	delete(mapOf(mapOf(config["burstObservatory"])["pingConfig"]), "connectivity")
	return config, nil
}

func (key serviceWorkerKey) address() string {
	return net.JoinHostPort("127.0.0.1", fmt.Sprint(key.Port))
}
