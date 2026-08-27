package multiproxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// wg-quick configuration parsing.
//
// A WireGuard config reaches a user as an INI-ish .conf file: that is what every
// provider hands out, what `wg-quick` reads, and what a QR code encodes. Asking
// them to transcribe it into JSON field by field is an invitation to typo a
// base64 key, which then fails at handshake time with nothing useful to say.
//
// So the .conf is parsed here into the same JSON the AddWireGuardUpstream
// binding already accepts, and the two paths converge immediately afterwards.
// The keys are carried through as text, exactly as written: validating them is
// ParseWireGuardConfigJSON's and the device's job, and doing it twice would mean
// two places to keep the rules the same.

// ParseWireGuardQuickConfig converts a wg-quick .conf into the JSON form
// AddWireGuardUpstream accepts.
//
// It understands the fields that describe a client tunnel:
//
//	[Interface]  PrivateKey, Address, DNS, MTU, ListenPort
//	[Peer]       PublicKey, PresharedKey, Endpoint, AllowedIPs, PersistentKeepalive
//
// wg-quick's shell hooks - PreUp, PostUp, PreDown, PostDown, Table, SaveConfig,
// FwMark - are recognised and ignored rather than rejected, because they appear
// in real configs and describe a host's routing table, which is not what this
// upstream is. Anything else unknown is an error: silently dropping a directive
// a user believed they had set is worse than saying it is not supported.
//
// Only the first [Peer] section is used. A multi-peer config describes a mesh,
// which an upstream is not; taking the first peer and saying so is clearer than
// half-supporting a topology the datapath has no way to express.
func ParseWireGuardQuickConfig(conf string) (string, error) {
	var (
		raw     wireGuardConfigJSON
		section string
		peers   int
	)

	type quickPeer struct {
		PublicKey           string   `json:"publicKey"`
		PresharedKey        string   `json:"presharedKey"`
		Endpoint            string   `json:"endpoint"`
		AllowedIPs          []string `json:"allowedIPs"`
		PersistentKeepalive uint16   `json:"persistentKeepalive"`
	}
	var peer quickPeer

	scanner := bufio.NewScanner(strings.NewReader(conf))
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		// wg-quick accepts both comment markers, and a trailing comment after a
		// value is common in configs people share.
		if i := strings.IndexAny(text, "#;"); i >= 0 {
			text = strings.TrimSpace(text[:i])
		}
		if text == "" {
			continue
		}

		if strings.HasPrefix(text, "[") && strings.HasSuffix(text, "]") {
			section = strings.ToLower(strings.TrimSpace(text[1 : len(text)-1]))
			if section == "peer" {
				peers++
			}
			continue
		}

		key, value, ok := strings.Cut(text, "=")
		if !ok {
			return "", fmt.Errorf("wireguard: line %d is not key = value: %q", line, text)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		switch section {
		case "interface":
			if err := applyQuickInterface(&raw, key, value, line); err != nil {
				return "", err
			}
		case "peer":
			// Everything past the first peer is read and discarded, so a
			// multi-peer file still parses rather than failing on its own syntax.
			if peers > 1 {
				continue
			}
			switch key {
			case "publickey":
				peer.PublicKey = value
			case "presharedkey":
				peer.PresharedKey = value
			case "endpoint":
				peer.Endpoint = value
			case "allowedips":
				peer.AllowedIPs = append(peer.AllowedIPs, splitList(value)...)
			case "persistentkeepalive":
				n, err := strconv.ParseUint(value, 10, 16)
				if err != nil {
					return "", fmt.Errorf("wireguard: line %d: PersistentKeepalive %q is not a number: %w", line, value, err)
				}
				peer.PersistentKeepalive = uint16(n)
			default:
				return "", fmt.Errorf("wireguard: line %d: unsupported [Peer] setting %q", line, key)
			}
		case "":
			return "", fmt.Errorf("wireguard: line %d: %q appears before any [Interface] or [Peer] section", line, key)
		default:
			return "", fmt.Errorf("wireguard: line %d: unknown section [%s]", line, section)
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("wireguard: reading config: %w", err)
	}

	if raw.PrivateKey == "" {
		return "", fmt.Errorf("wireguard: config has no [Interface] PrivateKey")
	}
	if peers == 0 {
		return "", fmt.Errorf("wireguard: config has no [Peer] section")
	}
	if peer.PublicKey == "" {
		return "", fmt.Errorf("wireguard: [Peer] has no PublicKey")
	}

	// Marshalled through the same struct the JSON path uses, so the two forms
	// cannot drift apart in field naming.
	out := struct {
		wireGuardConfigJSON
		Peers []quickPeer `json:"peers"`
	}{wireGuardConfigJSON: raw, Peers: []quickPeer{peer}}
	out.wireGuardConfigJSON.Peers = nil

	encoded, err := json.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("wireguard: encoding config: %w", err)
	}
	return string(encoded), nil
}

func applyQuickInterface(raw *wireGuardConfigJSON, key, value string, line int) error {
	switch key {
	case "privatekey":
		raw.PrivateKey = value
	case "address":
		raw.Addresses = append(raw.Addresses, splitList(value)...)
	case "dns":
		raw.DNS = append(raw.DNS, splitList(value)...)
	case "mtu":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("wireguard: line %d: MTU %q is not a number: %w", line, value, err)
		}
		raw.MTU = n
	case "listenport":
		n, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return fmt.Errorf("wireguard: line %d: ListenPort %q is not a number: %w", line, value, err)
		}
		raw.ListenPort = uint16(n)
	case "table", "fwmark", "savedconfig", "saveconfig", "preup", "postup", "predown", "postdown":
		// Host routing and shell hooks. They describe what wg-quick would do to a
		// machine's network configuration; this upstream terminates in-process and
		// has no such configuration to change.
	default:
		return fmt.Errorf("wireguard: line %d: unsupported [Interface] setting %q", line, key)
	}
	return nil
}

// splitList splits a comma-separated value, as wg-quick writes Address,
// AllowedIPs and DNS.
func splitList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
