package multiproxy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type PeerExportV2 struct {
	TailnetID        string `json:"tailnetId"`
	Hostname         string `json:"hostname"`
	CurrentIPv4      string `json:"currentIpv4"`
	CurrentIPv6      string `json:"currentIpv6"`
	SyntheticDNSName string `json:"syntheticDnsName"`
	SyntheticIPv6    string `json:"syntheticIpv6"`
	Kind             string `json:"kind"`
}

func syntheticQualifiedName(hostname string, upstream UpstreamID) string {
	name := strings.TrimSuffix(strings.ToLower(hostname), ".")
	if i := strings.IndexByte(name, '.'); i >= 0 {
		name = name[:i]
	}
	if name == "" {
		return ""
	}
	return fmt.Sprintf("%s.%s.proxy.", name, getStableHash(string(upstream)))
}

// GetTargetsJSONV2 returns the authoritative peer snapshot using names that
// match the synthetic DNS table and makes native-vs-synthetic addresses explicit.
func (e *Engine) GetTargetsJSONV2() string {
	e.targetMutex.RLock()
	out := make([]PeerExportV2, 0, len(e.targets))
	for _, rec := range e.targets {
		currentIPv4 := ""
		currentIPv6 := ""
		if rec.CurrentIPv4.IsValid() {
			currentIPv4 = rec.CurrentIPv4.String()
		}
		if rec.CurrentIPv6.IsValid() {
			currentIPv6 = rec.CurrentIPv6.String()
		}
		out = append(out, PeerExportV2{
			TailnetID:        string(rec.RequiredUpstream),
			Hostname:         rec.Hostname,
			CurrentIPv4:      currentIPv4,
			CurrentIPv6:      currentIPv6,
			SyntheticDNSName: syntheticQualifiedName(rec.Hostname, rec.RequiredUpstream),
			SyntheticIPv6:    rec.SyntheticIPv6.String(),
			Kind:             string(rec.Key.Kind),
		})
	}
	e.targetMutex.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].TailnetID != out[j].TailnetID {
			return out[i].TailnetID < out[j].TailnetID
		}
		if out[i].Hostname != out[j].Hostname {
			return out[i].Hostname < out[j].Hostname
		}
		return out[i].SyntheticIPv6 < out[j].SyntheticIPv6
	})

	b, err := json.Marshal(out)
	if err != nil {
		return "[]"
	}
	return string(b)
}
