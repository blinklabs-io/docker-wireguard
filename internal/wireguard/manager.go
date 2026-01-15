// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wireguard

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Peer represents a WireGuard peer
type Peer struct {
	PublicKey       string
	AllowedIPs      []string
	Endpoint        string
	LatestHandshake time.Time
	TransferRx      int64
	TransferTx      int64
}

// WireGuard public keys are 32 bytes (Curve25519)
const wireguardKeyLength = 32

// Maximum length for Linux interface names
const maxInterfaceNameLength = 15

var (
	ErrInvalidPubkey    = errors.New("invalid public key format")
	ErrInvalidIP        = errors.New("invalid IP address format")
	ErrCommandFailed    = errors.New("wg command failed")
	ErrInvalidInterface = errors.New("invalid interface name")
)

// validatePubkey validates that the given string is a valid base64-encoded
// WireGuard public key
func validatePubkey(pubkey string) error {
	decoded, err := base64.StdEncoding.DecodeString(pubkey)
	if err != nil {
		return fmt.Errorf("%w: invalid base64 encoding", ErrInvalidPubkey)
	}
	if len(decoded) != wireguardKeyLength {
		return fmt.Errorf("%w: key must be 32 bytes", ErrInvalidPubkey)
	}
	return nil
}

// validateIP validates that the given string is a valid IP address
func validateIP(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("%w: %s", ErrInvalidIP, ip)
	}
	return nil
}

// cidrSuffix returns the appropriate CIDR suffix for a single host IP
func cidrSuffix(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "/32" // default to IPv4
	}
	if parsed.To4() != nil {
		return "/32"
	}
	return "/128"
}

// validateInterface validates that the interface name is safe
func validateInterface(iface string) error {
	if iface == "" {
		return fmt.Errorf("%w: empty interface name", ErrInvalidInterface)
	}
	if len(iface) > maxInterfaceNameLength {
		return fmt.Errorf("%w: interface name too long", ErrInvalidInterface)
	}
	// Interface names should only contain alphanumeric characters, hyphens, and underscores
	for _, c := range iface {
		validChar := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_'
		if !validChar {
			return fmt.Errorf("%w: invalid character in interface name", ErrInvalidInterface)
		}
	}
	return nil
}

// AddPeer adds a WireGuard peer to the specified interface
func AddPeer(iface, pubkey, allowedIP string) error {
	if err := validateInterface(iface); err != nil {
		return err
	}
	if err := validatePubkey(pubkey); err != nil {
		return err
	}
	if err := validateIP(allowedIP); err != nil {
		return err
	}

	// Run: wg set <iface> peer <pubkey> allowed-ips <allowedIP>/<suffix>
	cmd := exec.Command( //nolint:gosec // inputs validated above
		"wg",
		"set",
		iface,
		"peer",
		pubkey,
		"allowed-ips",
		allowedIP+cidrSuffix(allowedIP),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %w: %s", ErrCommandFailed, err, string(output))
	}

	return nil
}

// RemovePeer removes a WireGuard peer from the specified interface
func RemovePeer(iface, pubkey string) error {
	if err := validateInterface(iface); err != nil {
		return err
	}
	if err := validatePubkey(pubkey); err != nil {
		return err
	}

	// Run: wg set <iface> peer <pubkey> remove
	cmd := exec.Command("wg", "set", iface, "peer", pubkey, "remove") //nolint:gosec // inputs validated above
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %w: %s", ErrCommandFailed, err, string(output))
	}

	return nil
}

// ListPeers lists all peers on the specified WireGuard interface
func ListPeers(iface string) ([]Peer, error) {
	if err := validateInterface(iface); err != nil {
		return nil, err
	}

	// Run: wg show <iface> dump
	cmd := exec.Command("wg", "show", iface, "dump") //nolint:gosec // inputs validated above
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %w: %s",
			ErrCommandFailed,
			err,
			string(output),
		)
	}

	return parseDump(string(output))
}

// parseDump parses the output of `wg show <iface> dump`
// Format: <interface line>\n<peer lines...>
// Interface line: private-key  public-key  listen-port  fwmark
// Peer line: public-key  preshared-key  endpoint  allowed-ips
// latest-handshake  transfer-rx  transfer-tx  persistent-keepalive
func parseDump(output string) ([]Peer, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 1 {
		return nil, nil
	}

	// Minimum number of fields expected in a peer line
	const minPeerFields = 8

	var peers []Peer
	// Skip the first line (interface info), process peer lines
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) < minPeerFields {
			continue
		}

		peer := Peer{
			PublicKey: fields[0],
			Endpoint:  fields[2],
		}

		// Parse allowed IPs (comma-separated)
		if fields[3] != "(none)" {
			peer.AllowedIPs = strings.Split(fields[3], ",")
		}

		// Parse latest handshake (Unix timestamp)
		if ts, err := strconv.ParseInt(fields[4], 10, 64); err == nil && ts > 0 {
			peer.LatestHandshake = time.Unix(ts, 0)
		}

		// Parse transfer stats
		if rx, err := strconv.ParseInt(fields[5], 10, 64); err == nil {
			peer.TransferRx = rx
		}
		if tx, err := strconv.ParseInt(fields[6], 10, 64); err == nil {
			peer.TransferTx = tx
		}

		peers = append(peers, peer)
	}

	return peers, nil
}
