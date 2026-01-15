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

package jwt

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the JWT claims for WireGuard peer management.
//
// This struct has both explicit Exp/Iat fields (int64) and embeds jwt.RegisteredClaims
// which also contains expiration data. This dual approach is intentional:
//
//  1. The explicit Exp and Iat fields (Unix timestamps as int64) match the technical
//     specification which defines these as numeric Unix timestamps in the JWT payload.
//     These are used for validation logic in ValidateToken.
//
//  2. The embedded jwt.RegisteredClaims is required for compatibility with the
//     github.com/golang-jwt/jwt/v5 library's parsing and validation mechanisms.
//     The library expects RegisteredClaims to be present for standard JWT operations.
//
// During token parsing, both sets of fields are populated from the same JSON payload.
// The explicit Exp field is used for our validation to ensure consistency with the spec.
type Claims struct {
	Sub       string `json:"sub"`
	Pubkey    string `json:"pubkey"`
	AllowedIP string `json:"allowed_ip"`
	Exp       int64  `json:"exp"`
	Iat       int64  `json:"iat"`
	jwt.RegisteredClaims
}

var (
	ErrInvalidPEM     = errors.New("invalid PEM format")
	ErrInvalidKeyType = errors.New(
		"invalid key type, expected Ed25519 public key",
	)
	ErrInvalidToken   = errors.New("invalid token")
	ErrTokenExpired   = errors.New("token expired")
	ErrInvalidSubject = errors.New("invalid subject, expected 'wg_peer'")
	ErrMissingClaims  = errors.New("missing required claims")
)

// LoadPublicKey reads a PEM-encoded Ed25519 public key from the given path
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidPEM
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ed25519Pub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}

	return ed25519Pub, nil
}

// ValidateToken validates a JWT token and returns the claims
func ValidateToken(
	tokenString string,
	pubKey ed25519.PublicKey,
) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (any, error) {
			// Verify the signing method is EdDSA
			if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, fmt.Errorf(
					"unexpected signing method: %v",
					token.Header["alg"],
				)
			}
			return pubKey, nil
		},
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	// Validate subject
	if claims.Sub != "wg_peer" {
		return nil, ErrInvalidSubject
	}

	// Validate required claims (including exp which is required per spec)
	if claims.Pubkey == "" || claims.AllowedIP == "" || claims.Exp == 0 {
		return nil, ErrMissingClaims
	}

	// Manual expiration check using our explicit Exp field (Unix timestamp).
	// This is done after ParseWithClaims because:
	// 1. ParseWithClaims validates using RegisteredClaims.ExpiresAt, but our spec defines
	//    expiration as a Unix timestamp in the "exp" field (int64), not the JWT NumericDate format.
	// 2. We need to ensure the explicit Exp field (which matches our spec) is validated,
	//    providing consistent behavior regardless of how the JWT library handles expiration.
	// 3. The library may have already caught expiration via RegisteredClaims (handled above),
	//    but this check ensures our spec-defined Exp field is also enforced.
	if claims.Exp < time.Now().Unix() {
		return nil, ErrTokenExpired
	}

	return claims, nil
}
