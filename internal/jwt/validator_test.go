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
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func generateTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	return pub, priv
}

func createTestToken(
	t *testing.T,
	priv ed25519.PrivateKey,
	claims map[string]any,
) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims(claims))
	tokenString, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return tokenString
}

func TestValidateToken_ValidToken(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	tokenString := createTestToken(t, priv, map[string]any{
		"sub":        "wg_peer",
		"pubkey":     base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"allowed_ip": "10.8.0.42",
		"exp":        time.Now().Add(time.Minute).Unix(),
		"iat":        time.Now().Unix(),
	})

	claims, err := ValidateToken(tokenString, pub)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if claims.Sub != "wg_peer" {
		t.Errorf("ValidateToken() sub = %v, want wg_peer", claims.Sub)
	}

	if claims.AllowedIP != "10.8.0.42" {
		t.Errorf("ValidateToken() allowed_ip = %v, want 10.8.0.42", claims.AllowedIP)
	}
}

func TestValidateToken_ExpiredToken(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	tokenString := createTestToken(t, priv, map[string]any{
		"sub":        "wg_peer",
		"pubkey":     base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"allowed_ip": "10.8.0.42",
		"exp":        time.Now().Add(-time.Minute).Unix(),
		"iat":        time.Now().Add(-2 * time.Minute).Unix(),
	})

	_, err := ValidateToken(tokenString, pub)
	if err == nil {
		t.Fatal("ValidateToken() expected error for expired token")
	}
}

func TestValidateToken_InvalidSubject(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	tokenString := createTestToken(t, priv, map[string]any{
		"sub":        "wrong_subject",
		"pubkey":     base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"allowed_ip": "10.8.0.42",
		"exp":        time.Now().Add(time.Minute).Unix(),
		"iat":        time.Now().Unix(),
	})

	_, err := ValidateToken(tokenString, pub)
	if err == nil {
		t.Fatal("ValidateToken() expected error for invalid subject")
	}
	if err != ErrInvalidSubject {
		t.Errorf("ValidateToken() error = %v, want ErrInvalidSubject", err)
	}
}

func TestValidateToken_MissingClaims(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	// Missing pubkey
	tokenString := createTestToken(t, priv, map[string]any{
		"sub":        "wg_peer",
		"allowed_ip": "10.8.0.42",
		"exp":        time.Now().Add(time.Minute).Unix(),
		"iat":        time.Now().Unix(),
	})

	_, err := ValidateToken(tokenString, pub)
	if err == nil {
		t.Fatal("ValidateToken() expected error for missing claims")
	}
}

func TestValidateToken_WrongKey(t *testing.T) {
	_, priv := generateTestKeyPair(t)
	wrongPub, _ := generateTestKeyPair(t)

	tokenString := createTestToken(t, priv, map[string]any{
		"sub":        "wg_peer",
		"pubkey":     base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"allowed_ip": "10.8.0.42",
		"exp":        time.Now().Add(time.Minute).Unix(),
		"iat":        time.Now().Unix(),
	})

	_, err := ValidateToken(tokenString, wrongPub)
	if err == nil {
		t.Fatal("ValidateToken() expected error for wrong key")
	}
}
