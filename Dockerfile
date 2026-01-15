# Build stage
FROM ghcr.io/blinklabs-io/go:1.25.5-1 AS build

ARG VERSION
ARG COMMIT_HASH
ENV VERSION=${VERSION}
ENV COMMIT_HASH=${COMMIT_HASH}

WORKDIR /code
RUN go env -w GOCACHE=/go-cache
RUN go env -w GOMODCACHE=/gomod-cache
COPY go.* .
RUN --mount=type=cache,target=/gomod-cache go mod download
COPY . .
RUN --mount=type=cache,target=/gomod-cache --mount=type=cache,target=/go-cache make build

# Runtime stage
FROM debian:bookworm-slim AS wg-peer-api
RUN apt-get update -y && \
  apt-get install -y --no-install-recommends \
    ca-certificates \
    iptables \
    iproute2 \
    procps \
    wireguard-tools && \
  rm -rf /var/lib/apt/lists/*
COPY --from=build /code/wg-peer-api /bin/
COPY bin/entrypoint /bin/entrypoint
RUN chmod +x /bin/entrypoint

# WireGuard UDP port
EXPOSE 51820/udp
# API port
EXPOSE 8080/tcp

# Environment defaults
ENV WG_PORT=51820
ENV WG_SUBNET=10.8.0.1/24
ENV NAT_DEVICE=eth0
ENV API_LISTEN=:8080
ENV JWT_PUBLIC_KEY_FILE=/etc/wireguard/jwt-verify.pub

# Volume for WireGuard config and JWT key
VOLUME /etc/wireguard

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ip link show wg0 >/dev/null 2>&1 && pgrep wg-peer-api >/dev/null || exit 1

ENTRYPOINT ["/bin/entrypoint"]

FROM wg-peer-api AS final
