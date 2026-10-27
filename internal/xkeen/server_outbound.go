package xkeen

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"xkeen-panel/internal/models"
)

// BuildServerOutbound keeps native JSON endpoint parameters intact. Local
// application changes only the tag and the template's policy-routing mark.
func BuildServerOutbound(server models.Server, tag string, template map[string]interface{}) (map[string]interface{}, error) {
	if len(server.RawProfile) > 0 {
		return BuildProfileEntry(server, tag, template)
	}
	var outbound map[string]interface{}
	var err error
	if len(server.RawOutbound) != 0 {
		outbound, err = decodeServerOutbound(server.RawOutbound)
		if err != nil {
			return nil, err
		}
		if hasOutboundDependency(outbound) {
			return nil, fmt.Errorf("составной outbound требует отдельной конфигурации")
		}
		if _, _, _, err := outboundMetadata(outbound); err != nil {
			return nil, err
		}
	} else {
		switch {
		case strings.HasPrefix(server.RawURI, "vless://"):
			params, parseErr := ParseVLESS(server.RawURI)
			if parseErr != nil || params.Address == "" || params.UUID == "" || params.Port < 1 || params.Port > 65535 {
				return nil, fmt.Errorf("некорректная VLESS-ссылка")
			}
			parsed, _ := url.Parse(server.RawURI)
			query := parsed.Query()
			if params.Network == "grpc" {
				for _, key := range []string{"serviceName", "grpcServiceName", "path"} {
					if value := query.Get(key); value != "" {
						params.Path = value
						break
					}
				}
			}
			outbound = buildOutboundFromURI(params, tag, detectOutboundFormat(template))
			stream := mapOf(outbound["streamSettings"])
			if params.Network == "grpc" {
				grpc := mapOf(stream["grpcSettings"])
				if authority := query.Get("authority"); authority != "" {
					grpc["authority"] = authority
				}
				if query.Has("multiMode") {
					grpc["multiMode"] = boolQuery(query.Get("multiMode"))
				}
			}
			if params.Network == "httpupgrade" {
				upgrade := map[string]interface{}{}
				if params.Path != "" {
					upgrade["path"] = params.Path
				}
				if params.Host != "" {
					upgrade["host"] = params.Host
				}
				stream["httpupgradeSettings"] = upgrade
			}
		case strings.HasPrefix(server.RawURI, "hy2://"), strings.HasPrefix(server.RawURI, "hysteria2://"):
			outbound, err = buildHysteria2Outbound(server.RawURI, tag)
			if err != nil {
				return nil, err
			}
		case strings.HasPrefix(server.RawURI, "vmess://"):
			outbound, err = buildVMessURIOutbound(server.RawURI, tag)
		case strings.HasPrefix(server.RawURI, "trojan://"):
			outbound, err = buildTrojanURIOutbound(server.RawURI, tag)
		case strings.HasPrefix(server.RawURI, "ss://"):
			outbound, err = buildShadowsocksURIOutbound(server.RawURI, tag)
		default:
			return nil, fmt.Errorf("для этого сервера нет поддерживаемого Xray outbound")
		}
		if err != nil {
			return nil, err
		}
	}
	outbound["tag"] = tag
	if sockopt := mapOf(mapOf(template["streamSettings"])["sockopt"]); sockopt != nil {
		if mark, ok := sockopt["mark"]; ok {
			stream := mapOf(outbound["streamSettings"])
			if stream == nil {
				stream = map[string]interface{}{}
				outbound["streamSettings"] = stream
			}
			options := mapOf(stream["sockopt"])
			if options == nil {
				options = map[string]interface{}{}
				stream["sockopt"] = options
			}
			options["mark"] = mark
		}
	}
	return outbound, nil
}

func CanBuildServer(server models.Server) bool {
	_, err := BuildServerOutbound(server, "", nil)
	return err == nil
}

// ServerIdentity is opaque for JSON nodes, never a credential-bearing URI.
// Legacy URI identities remain unchanged for compatibility with stored state.
func ServerIdentity(server models.Server) string {
	if len(server.RawProfile) > 0 {
		return ProfileIdentity(server)
	}
	if len(server.RawOutbound) == 0 {
		return server.RawURI
	}
	outbound, err := decodeServerOutbound(server.RawOutbound)
	if err != nil {
		return ""
	}
	delete(outbound, "tag")
	stream := mapOf(outbound["streamSettings"])
	if sockopt := mapOf(stream["sockopt"]); sockopt != nil {
		delete(sockopt, "mark")
		if len(sockopt) == 0 {
			delete(stream, "sockopt")
		}
	}
	proto, _ := outbound["protocol"].(string)
	if proto == "vless" {
		normalizeVLESSIdentity(outbound)
		if stream == nil {
			stream = map[string]interface{}{}
			outbound["streamSettings"] = stream
		}
		if network, _ := stream["network"].(string); canonicalNetwork(network) == "tcp" {
			stream["network"] = "tcp"
		}
		if security, _ := stream["security"].(string); security == "none" || security == "" {
			delete(stream, "security")
		}
	}
	if len(stream) == 0 {
		delete(outbound, "streamSettings")
	}
	canonical, err := json.Marshal(outbound)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(canonical)
	return "xray-json://" + hex.EncodeToString(digest[:])
}

func normalizeVLESSIdentity(outbound map[string]interface{}) {
	settings := mapOf(outbound["settings"])
	if settings == nil {
		return
	}
	if vnext, ok := settings["vnext"].([]interface{}); ok && len(vnext) == 1 && len(settings) == 1 {
		entry := mapOf(vnext[0])
		if users, ok := entry["users"].([]interface{}); ok && len(users) == 1 {
			user := mapOf(users[0])
			flat := make(map[string]interface{}, len(entry)+len(user))
			conflict := false
			for key, value := range entry {
				if key != "users" {
					flat[key] = value
				}
			}
			for key, value := range user {
				if _, exists := flat[key]; exists {
					conflict = true
				}
				flat[key] = value
			}
			if !conflict {
				settings = flat
				outbound["settings"] = settings
			}
		}
	}
	if encryption, _ := settings["encryption"].(string); encryption == "" {
		settings["encryption"] = "none"
	}
	if value, ok := settings["level"]; ok && jsonPort(value) == 0 {
		delete(settings, "level")
	}
}

func hasOutboundDependency(outbound map[string]interface{}) bool {
	if tag, _ := mapOf(outbound["proxySettings"])["tag"].(string); strings.TrimSpace(tag) != "" {
		return true
	}
	if tag, _ := mapOf(mapOf(outbound["streamSettings"])["sockopt"])["dialerProxy"].(string); strings.TrimSpace(tag) != "" {
		return true
	}
	return false
}

func outboundMetadata(outbound map[string]interface{}) (string, int, string, error) {
	proto, _ := outbound["protocol"].(string)
	settings := mapOf(outbound["settings"])
	endpoint := settings
	credential := ""
	requireCredential := true
	switch proto {
	case "vless", "vmess":
		if entries, ok := settings["vnext"].([]interface{}); ok {
			if len(entries) != 1 {
				return "", 0, "", fmt.Errorf("outbound не является одиночным сервером")
			}
			endpoint = mapOf(entries[0])
			if users, _ := endpoint["users"].([]interface{}); len(users) == 1 {
				credential, _ = mapOf(users[0])["id"].(string)
			}
		} else {
			credential, _ = settings["id"].(string)
		}
	case "trojan", "shadowsocks":
		if entries, ok := settings["servers"].([]interface{}); ok {
			if len(entries) != 1 {
				return "", 0, "", fmt.Errorf("outbound не является одиночным сервером")
			}
			endpoint = mapOf(entries[0])
		}
		credential, _ = endpoint["password"].(string)
	case "http", "socks":
		requireCredential = false
		if entries, ok := settings["servers"].([]interface{}); ok {
			if len(entries) != 1 {
				return "", 0, "", fmt.Errorf("outbound не является одиночным сервером")
			}
			endpoint = mapOf(entries[0])
		}
	case "hysteria":
		if jsonPort(settings["version"]) != 2 {
			return "", 0, "", fmt.Errorf("поддерживается Hysteria версии 2")
		}
		credential, _ = mapOf(mapOf(outbound["streamSettings"])["hysteriaSettings"])["auth"].(string)
		proto = "hysteria2"
	default:
		return "", 0, "", fmt.Errorf("неподдерживаемый протокол Xray outbound")
	}
	address, _ := endpoint["address"].(string)
	port := jsonPort(endpoint["port"])
	if strings.TrimSpace(address) == "" || port < 1 || port > 65535 || (requireCredential && credential == "") {
		return "", 0, "", fmt.Errorf("outbound не содержит полный адрес и параметры доступа")
	}
	return address, port, proto, nil
}

func jsonPort(value interface{}) int {
	switch number := value.(type) {
	case json.Number:
		parsed, _ := strconv.Atoi(string(number))
		return parsed
	case float64:
		if number != float64(int(number)) {
			return -1
		}
		return int(number)
	case int:
		return number
	case string:
		parsed, _ := strconv.Atoi(number)
		return parsed
	}
	return 0
}
