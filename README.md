# docker-wireguard

WireGuard VPN container with JWT-authenticated peer management API for the NABU VPN service.

## Overview

This container provides a WireGuard VPN server with a REST API for dynamic peer management. The API accepts JWT-authenticated requests from the vpn-indexer to add and remove WireGuard peers on-the-fly.

## Quick Start

```bash
docker run -d \
  --name wireguard \
  --cap-add=NET_ADMIN \
  -e WG_ENDPOINT=vpn.example.com:51820 \
  -e WG_PRIVATE_KEY=$(wg genkey) \
  -v /path/to/jwt-verify.pub:/etc/wireguard/jwt-verify.pub:ro \
  -p 51820:51820/udp \
  -p 8080:8080 \
  ghcr.io/blinklabs-io/docker-wireguard:latest
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WG_PRIVATE_KEY` | (generated) | Server private key (base64). If not provided, an ephemeral key is generated. |
| `WG_PORT` | `51820` | WireGuard UDP listen port |
| `WG_SUBNET` | `10.8.0.1/24` | Server address and subnet |
| `WG_ENDPOINT` | (required) | Public endpoint for clients (e.g., `vpn.example.com:51820`) |
| `NAT_DEVICE` | `eth0` | Outbound NAT interface |
| `API_LISTEN` | `:8080` | Peer API listen address |
| `JWT_PUBLIC_KEY_FILE` | `/etc/wireguard/jwt-verify.pub` | Path to Ed25519 public key for JWT verification |
| `ENABLE_NAT` | `1` | Enable NAT masquerading (set to `0` to disable) |
| `DEBUG` | `0` | Enable debug logging |
| `USER_STARTUP_SCRIPT` | `/usr/local/bin/entrypoint-user.sh` | Optional user startup script |

## API Endpoints

### Health Check

```
GET /health
```

Returns the health status of the API.

**Response:**
```json
{"status": "healthy"}
```

### Server Info

```
GET /info
```

Returns the server's public key and endpoint.

**Response:**
```json
{
  "server_pubkey": "base64_encoded_public_key",
  "endpoint": "vpn.example.com:51820"
}
```

### Add Peer

```
POST /peer
Content-Type: application/json

{
  "jwt": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "pubkey": "client_wireguard_public_key"
}
```

Adds a WireGuard peer. Requires a valid JWT token.

**Response:**
```json
{
  "success": true,
  "server_pubkey": "base64_encoded_public_key",
  "endpoint": "vpn.example.com:51820",
  "allowed_ips": "0.0.0.0/0"
}
```

### Remove Peer

```
DELETE /peer
Content-Type: application/json

{
  "jwt": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "pubkey": "client_wireguard_public_key"
}
```

Removes a WireGuard peer. Requires a valid JWT token.

**Response:**
```json
{"success": true}
```

### Prometheus Metrics

```
GET /metrics
```

Returns Prometheus-formatted metrics for monitoring.

**Available Metrics:**
- `wg_peers_added_total` - Total number of WireGuard peers added
- `wg_peers_removed_total` - Total number of WireGuard peers removed
- `wg_active_peers` - Current number of active WireGuard peers
- `wg_peer_operation_errors_total` - Peer operation errors by type (add/remove)
- `wg_api_requests_total` - API requests by endpoint, method, and status code
- `wg_api_request_duration_seconds` - API request duration histogram
- `wg_jwt_validation_errors_total` - JWT validation errors

## JWT Requirements

JWTs must be:
- Signed with Ed25519 (EdDSA algorithm)
- Have `sub` claim set to `wg_peer`
- Include `pubkey` claim matching the request pubkey
- Include `allowed_ip` claim with the client's assigned IP
- Have `exp` (expiration) claim set (recommended: 60 seconds from issuance)

**Example JWT Claims:**
```json
{
  "sub": "wg_peer",
  "pubkey": "client_wireguard_public_key",
  "allowed_ip": "10.8.0.42",
  "exp": 1705123516,
  "iat": 1705123456
}
```

## Security

- Container requires `NET_ADMIN` capability for WireGuard kernel operations
- Private keys should be stored in secrets, never logged
- Default firewall policy is DROP; only forwarded traffic from wg0 is allowed
- API mutations require valid, non-expired JWT
- Network policies should restrict API access to trusted services only

## Building

```bash
# Build Docker image
docker build -t wireguard:latest .

# Build Go binary locally
go build -o wg-peer-api ./cmd/wg-peer-api

# Run tests
go test ./...
```

## Kubernetes Deployment

See the [vpn-infrastructure](https://github.com/blinklabs-io/vpn-infrastructure) repository for Helm charts and deployment configurations.

## License

Copyright 2026 Blink Labs Software

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
