package xkeen

import (
	"encoding/json"
	"errors"
	"fmt"

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
	for i, server := range servers {
		out, err := BuildServerOutbound(server, fmt.Sprintf("%s%d", selector, i), nil)
		if err != nil || len(server.RawProfile) != 0 || !permittedServiceOutbound(out) {
			return models.Server{}, errors.New("в мультипуле оказался неподдерживаемый узел")
		}
		outbounds = append(outbounds, out)
	}
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
	return models.Server{Protocol: "xray-profile", RawProfile: raw}, err
}
