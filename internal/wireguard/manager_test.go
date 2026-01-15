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
	"testing"
)

func TestValidatePubkey(t *testing.T) {
	tests := []struct {
		name    string
		pubkey  string
		wantErr bool
	}{
		{
			name:    "valid pubkey",
			pubkey:  base64.StdEncoding.EncodeToString(make([]byte, 32)),
			wantErr: false,
		},
		{
			name:    "invalid base64",
			pubkey:  "not-valid-base64!!!",
			wantErr: true,
		},
		{
			name:    "wrong length",
			pubkey:  base64.StdEncoding.EncodeToString(make([]byte, 16)),
			wantErr: true,
		},
		{
			name:    "empty string",
			pubkey:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePubkey(tt.pubkey)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePubkey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{
			name:    "valid IPv4",
			ip:      "10.8.0.42",
			wantErr: false,
		},
		{
			name:    "valid IPv6",
			ip:      "::1",
			wantErr: false,
		},
		{
			name:    "invalid IP",
			ip:      "not-an-ip",
			wantErr: true,
		},
		{
			name:    "empty string",
			ip:      "",
			wantErr: true,
		},
		{
			name:    "IP with CIDR",
			ip:      "10.8.0.0/24",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIP(tt.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateIP() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateInterface(t *testing.T) {
	tests := []struct {
		name    string
		iface   string
		wantErr bool
	}{
		{
			name:    "valid interface",
			iface:   "wg0",
			wantErr: false,
		},
		{
			name:    "valid with hyphen",
			iface:   "wg-test",
			wantErr: false,
		},
		{
			name:    "valid with underscore",
			iface:   "wg_test",
			wantErr: false,
		},
		{
			name:    "empty string",
			iface:   "",
			wantErr: true,
		},
		{
			name:    "too long",
			iface:   "this-is-way-too-long",
			wantErr: true,
		},
		{
			name:    "invalid characters",
			iface:   "wg0; rm -rf /",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateInterface(tt.iface)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateInterface() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseDump(t *testing.T) {
	// Example output from `wg show wg0 dump`
	dumpOutput := `privatekey	publickey	51820	off
peer1pubkey	(none)	1.2.3.4:51820	10.8.0.2/32	1705123456	1024	2048	25
peer2pubkey	(none)	(none)	10.8.0.3/32	0	0	0	off`

	peers, err := parseDump(dumpOutput)
	if err != nil {
		t.Fatalf("parseDump() error = %v", err)
	}

	if len(peers) != 2 {
		t.Fatalf("parseDump() got %d peers, want 2", len(peers))
	}

	if peers[0].PublicKey != "peer1pubkey" {
		t.Errorf("parseDump() first peer pubkey = %v, want peer1pubkey", peers[0].PublicKey)
	}

	if peers[0].TransferRx != 1024 {
		t.Errorf("parseDump() first peer TransferRx = %v, want 1024", peers[0].TransferRx)
	}
}

func TestCidrSuffix(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want string
	}{
		{
			name: "IPv4 address",
			ip:   "10.8.0.42",
			want: "/32",
		},
		{
			name: "IPv6 address",
			ip:   "2001:db8::1",
			want: "/128",
		},
		{
			name: "IPv6 loopback",
			ip:   "::1",
			want: "/128",
		},
		{
			name: "invalid IP",
			ip:   "not-an-ip",
			want: "/32",
		},
		{
			name: "empty string",
			ip:   "",
			want: "/32",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cidrSuffix(tt.ip)
			if got != tt.want {
				t.Errorf("cidrSuffix(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestParseDumpEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantPeers int
		wantErr   bool
	}{
		{
			name:      "empty string",
			input:     "",
			wantPeers: 0,
			wantErr:   false,
		},
		{
			name:      "whitespace only",
			input:     "   \t\n  ",
			wantPeers: 0,
			wantErr:   false,
		},
		{
			name:      "interface line only",
			input:     "privatekey\tpublickey\t51820\toff",
			wantPeers: 0,
			wantErr:   false,
		},
		{
			name: "single peer",
			input: `privatekey	publickey	51820	off
peer1pubkey	(none)	1.2.3.4:51820	10.8.0.2/32	1705123456	1024	2048	25`,
			wantPeers: 1,
			wantErr:   false,
		},
		{
			name: "malformed peer line with fewer than 8 fields",
			input: `privatekey	publickey	51820	off
peer1pubkey	(none)	1.2.3.4:51820`,
			wantPeers: 0,
			wantErr:   false,
		},
		{
			name: "valid peer followed by malformed peer",
			input: `privatekey	publickey	51820	off
peer1pubkey	(none)	1.2.3.4:51820	10.8.0.2/32	1705123456	1024	2048	25
malformed	line	only`,
			wantPeers: 1,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peers, err := parseDump(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDump() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(peers) != tt.wantPeers {
				t.Errorf("parseDump() got %d peers, want %d", len(peers), tt.wantPeers)
			}
		})
	}
}
