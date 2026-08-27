// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"time"

	"tailscale.com/net/netcheck"
)

type NetcheckReportJSON struct {
	UDP                   bool                `json:"udp"`
	IPv4                  bool                `json:"ipv4"`
	IPv6                  bool                `json:"ipv6"`
	MappingVariesByDestIP bool                `json:"mappingVariesByDestIP"`
	UPnP                  bool                `json:"upnp"`
	PMP                   bool                `json:"pmp"`
	CaptivePortal         bool                `json:"captivePortal"`
	PreferredDERP         int                 `json:"preferredDERP"`
	DERPLatencies         []DERPRegionLatency `json:"derpLatencies"`
	Error                 string              `json:"error,omitempty"`
}

type DERPRegionLatency struct {
	RegionID   int     `json:"regionID"`
	RegionCode string  `json:"regionCode"`
	RegionName string  `json:"regionName"`
	LatencyMs  float64 `json:"latencyMs"`
}

// RunNetcheck performs live NAT and DERP latency diagnostic probing and returns
// a JSON string representation of the diagnostic report.
func RunNetcheck() string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	b := androidDNSBackend.Load()
	if b == nil || b.backend == nil {
		return errorJSON("Tailscale engine unavailable")
	}

	dm := b.backend.DERPMap()
	if dm == nil {
		return errorJSON("DERP region map unavailable")
	}

	if b.netMon == nil {
		return errorJSON("Network monitor unavailable")
	}

	c := &netcheck.Client{
		Logf:   log.Printf,
		NetMon: b.netMon,
	}

	report, err := c.GetReport(ctx, dm, nil)
	if err != nil {
		return errorJSON(fmt.Sprintf("Netcheck probe failed: %v", err))
	}

	res := NetcheckReportJSON{
		UDP:                   report.UDP,
		IPv4:                  report.IPv4,
		IPv6:                  report.IPv6,
		MappingVariesByDestIP: report.MappingVariesByDestIP.EqualBool(true),
		UPnP:                  report.UPnP.EqualBool(true),
		PMP:                   report.PMP.EqualBool(true),
		CaptivePortal:         report.CaptivePortal.EqualBool(true),
		PreferredDERP:         int(report.PreferredDERP),
		DERPLatencies:         make([]DERPRegionLatency, 0),
	}

	for regID, dur := range report.RegionLatency {
		regIDInt := int(regID)
		reg, ok := dm.Regions[regID]
		code := fmt.Sprintf("derp-%d", regIDInt)
		name := fmt.Sprintf("Region %d", regIDInt)
		if ok {
			code = reg.RegionCode
			name = reg.RegionName
		}
		res.DERPLatencies = append(res.DERPLatencies, DERPRegionLatency{
			RegionID:   regIDInt,
			RegionCode: code,
			RegionName: name,
			LatencyMs:  float64(dur.Milliseconds()),
		})
	}

	sort.Slice(res.DERPLatencies, func(i, j int) bool {
		return res.DERPLatencies[i].LatencyMs < res.DERPLatencies[j].LatencyMs
	})

	data, err := json.Marshal(res)
	if err != nil {
		return errorJSON(fmt.Sprintf("Failed to encode report JSON: %v", err))
	}
	return string(data)
}

func errorJSON(msg string) string {
	data, _ := json.Marshal(NetcheckReportJSON{Error: msg})
	return string(data)
}
