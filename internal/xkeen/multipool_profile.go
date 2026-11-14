package xkeen

import (
	"encoding/json"
	"errors"
	"sort"

	"xkeen-panel/internal/models"
)

// MaxMultiPoolMembers is the maximum number of outbounds the guarded profile
// compiler accepts. The caller selects a deterministic subset for larger pools.
const MaxMultiPoolMembers = 256

// MultiPoolProfile makes one isolated, probed VPN worker for the whole pool.
// Membership order must be stable so equivalent pools share a worker.
func MultiPoolProfile(servers []models.Server) (models.Server, error) {
	if len(servers) == 0 || len(servers) > MaxMultiPoolMembers {
		return models.Server{}, errors.New("недопустимое число узлов мультипула")
	}
	const selector = "member-"
	outbounds := make([]interface{}, 0, len(servers))
	for _, server := range servers {
		id := ServiceTargetID(server)
		out, err := BuildServerOutbound(server, selector+id, nil)
		if err != nil || id == "" || len(server.RawProfile) != 0 || !permittedServiceOutbound(out) {
			return models.Server{}, errors.New("в мультипуле оказался неподдерживаемый узел")
		}
		outbounds = append(outbounds, out)
	}
	// Measurement order can change on every check while membership stays the
	// same. An identical set must always produce the same worker generation.
	sort.Slice(outbounds, func(i, j int) bool {
		return mapOf(outbounds[i])["tag"].(string) < mapOf(outbounds[j])["tag"].(string)
	})
	// serviceWorkerConfig adds the terminal blackhole, protects resolver
	// traffic through the same balancer, and sets blackhole as fallbackTag.
	profile := map[string]interface{}{
		"outbounds": outbounds,
		"routing": map[string]interface{}{
			"balancers": []interface{}{balancerBlock("pool", selector)},
			"rules": []interface{}{map[string]interface{}{
				"type": "field", "network": "tcp,udp", "balancerTag": "pool",
			}},
		},
		"observatory": observatoryBlock(selector, len(servers)),
	}
	raw, err := json.Marshal(profile)
	return models.Server{Protocol: "xray-profile", RawProfile: raw, GeneratedPool: true}, err
}
