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

package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blinklabs-io/docker-wireguard/internal/jwt"
	"github.com/blinklabs-io/docker-wireguard/internal/metrics"
	"github.com/blinklabs-io/docker-wireguard/internal/version"
	"github.com/blinklabs-io/docker-wireguard/internal/wireguard"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	listenAddr   string
	jwtKeyPath   string
	wgInterface  string
	wgPublicKey  string
	wgEndpoint   string
	jwtPublicKey ed25519.PublicKey
	debug        bool
	showVersion  bool
)

// Request/Response types
type PeerRequest struct {
	JWT    string `json:"jwt"`
	Pubkey string `json:"pubkey"`
}

type HealthResponse struct {
	Status string `json:"status"`
}

type InfoResponse struct {
	ServerPubkey string `json:"server_pubkey"`
	Endpoint     string `json:"endpoint"`
}

type AddPeerResponse struct {
	Success      bool   `json:"success"`
	ServerPubkey string `json:"server_pubkey"`
	Endpoint     string `json:"endpoint"`
	AllowedIPs   string `json:"allowed_ips"`
}

type DeletePeerResponse struct {
	Success bool `json:"success"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func main() {
	// Parse flags
	flag.StringVar(&listenAddr, "listen", ":8080", "API listen address")
	flag.StringVar(
		&jwtKeyPath,
		"jwt-public-key",
		"/etc/wireguard/jwt-verify.pub",
		"Path to Ed25519 public key file",
	)
	flag.StringVar(&wgInterface, "interface", "wg0", "WireGuard interface name")
	flag.BoolVar(&showVersion, "version", false, "Show version and exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("wg-peer-api %s\n", version.GetVersionString())
		os.Exit(0)
	}

	// Read environment variables
	wgPublicKey = os.Getenv("WG_PUBLIC_KEY")
	wgEndpoint = os.Getenv("WG_ENDPOINT")
	debug = os.Getenv("DEBUG") != ""

	if wgPublicKey == "" {
		log.Fatal("WG_PUBLIC_KEY environment variable is required")
	}
	if wgEndpoint == "" {
		log.Fatal("WG_ENDPOINT environment variable is required")
	}

	// Load JWT public key
	var err error
	jwtPublicKey, err = jwt.LoadPublicKey(jwtKeyPath)
	if err != nil {
		log.Fatalf("Failed to load JWT public key: %v", err)
	}
	log.Printf("Loaded JWT public key from %s", jwtKeyPath)

	// Setup HTTP routes
	http.HandleFunc("/health", instrumentHandler("/health", handleHealth))
	http.HandleFunc("/info", instrumentHandler("/info", handleInfo))
	http.HandleFunc("/peer", instrumentHandler("/peer", handlePeer))
	http.Handle("/metrics", promhttp.Handler())

	// Start server
	log.Printf(
		"Starting WireGuard Peer API %s on %s",
		version.GetVersionString(),
		listenAddr,
	)
	log.Printf("WireGuard interface: %s", wgInterface)
	log.Printf("WireGuard endpoint: %s", wgEndpoint)

	server := &http.Server{
		Addr:         listenAddr,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// instrumentHandler wraps a handler to log requests and record metrics
func instrumentHandler(endpoint string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if debug {
			log.Printf("-> %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		}

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		handler(wrapped, r)

		duration := time.Since(start)
		if debug {
			log.Printf("<- %s %s took %v", r.Method, r.URL.Path, duration)
		}

		// Record metrics
		metrics.APIRequests.WithLabelValues(endpoint, r.Method, strconv.Itoa(wrapped.statusCode)).Inc()
		metrics.APIRequestDuration.WithLabelValues(endpoint, r.Method).Observe(duration.Seconds())
	}
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("Failed to encode JSON response: %v", err)
	}
}

// writeError writes an error response
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, ErrorResponse{Error: message})
}

// writePeerError writes an appropriate error response for peer operations.
// It returns a 400 Bad Request for validation errors (containing "invalid")
// or a 500 Internal Server Error for other failures.
func writePeerError(w http.ResponseWriter, err error, operation string) {
	if strings.Contains(err.Error(), "invalid") {
		writeError(w, http.StatusBadRequest, err.Error())
	} else {
		writeError(w, http.StatusInternalServerError, "failed to "+operation+" peer")
	}
}

// truncateString safely truncates a string for logging
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// handleHealth handles GET /health
func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	writeJSON(w, http.StatusOK, HealthResponse{Status: "healthy"})
}

// handleInfo handles GET /info
func handleInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	writeJSON(w, http.StatusOK, InfoResponse{
		ServerPubkey: wgPublicKey,
		Endpoint:     wgEndpoint,
	})
}

// handlePeer handles POST /peer and DELETE /peer
func handlePeer(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		handleAddPeer(w, r)
	case http.MethodDelete:
		handleDeletePeer(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// validatePeerRequest parses and validates a peer request, returning the validated claims
func validatePeerRequest(w http.ResponseWriter, r *http.Request) (*jwt.Claims, bool) {
	var req PeerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return nil, false
	}

	if req.JWT == "" {
		writeError(w, http.StatusBadRequest, "jwt is required")
		return nil, false
	}
	if req.Pubkey == "" {
		writeError(w, http.StatusBadRequest, "pubkey is required")
		return nil, false
	}

	claims, err := jwt.ValidateToken(req.JWT, jwtPublicKey)
	if err != nil {
		log.Printf("JWT validation failed: %v", err)
		metrics.JWTValidationErrors.Inc()
		writeError(w, http.StatusUnauthorized, "invalid or expired token")
		return nil, false
	}

	if claims.Pubkey != req.Pubkey {
		writeError(w, http.StatusBadRequest, "pubkey mismatch: JWT pubkey does not match request pubkey")
		return nil, false
	}

	return claims, true
}

// handleAddPeer handles POST /peer
func handleAddPeer(w http.ResponseWriter, r *http.Request) {
	claims, ok := validatePeerRequest(w, r)
	if !ok {
		return
	}

	// Add peer to WireGuard
	if err := wireguard.AddPeer(
		wgInterface,
		claims.Pubkey,
		claims.AllowedIP,
	); err != nil {
		log.Printf("Failed to add peer: %v", err)
		metrics.PeerOperationErrors.WithLabelValues("add").Inc()
		writePeerError(w, err, "add")
		return
	}

	metrics.PeersAdded.Inc()
	metrics.ActivePeers.Inc()
	log.Printf(
		"Added peer: pubkey=%s allowed_ip=%s",
		truncateString(claims.Pubkey, 16),
		claims.AllowedIP,
	)

	writeJSON(w, http.StatusOK, AddPeerResponse{
		Success:      true,
		ServerPubkey: wgPublicKey,
		Endpoint:     wgEndpoint,
		// Client-side AllowedIPs: route all traffic through the VPN tunnel
		AllowedIPs: "0.0.0.0/0",
	})
}

// handleDeletePeer handles DELETE /peer
func handleDeletePeer(w http.ResponseWriter, r *http.Request) {
	claims, ok := validatePeerRequest(w, r)
	if !ok {
		return
	}

	// Remove peer from WireGuard
	if err := wireguard.RemovePeer(wgInterface, claims.Pubkey); err != nil {
		log.Printf("Failed to remove peer: %v", err)
		metrics.PeerOperationErrors.WithLabelValues("remove").Inc()
		writePeerError(w, err, "remove")
		return
	}

	metrics.PeersRemoved.Inc()
	metrics.ActivePeers.Dec()
	log.Printf("Removed peer: pubkey=%s", truncateString(claims.Pubkey, 16))

	writeJSON(w, http.StatusOK, DeletePeerResponse{Success: true})
}
