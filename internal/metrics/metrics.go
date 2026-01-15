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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	PeersAdded = promauto.NewCounter(prometheus.CounterOpts{
		Name: "wg_peers_added_total",
		Help: "Total number of WireGuard peers added",
	})

	PeersRemoved = promauto.NewCounter(prometheus.CounterOpts{
		Name: "wg_peers_removed_total",
		Help: "Total number of WireGuard peers removed",
	})

	PeerOperationErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "wg_peer_operation_errors_total",
		Help: "Total number of peer operation errors by type",
	}, []string{"operation"})

	APIRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "wg_api_requests_total",
		Help: "Total API requests by endpoint and status code",
	}, []string{"endpoint", "method", "status"})

	APIRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "wg_api_request_duration_seconds",
		Help:    "API request duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"endpoint", "method"})

	JWTValidationErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "wg_jwt_validation_errors_total",
		Help: "Total number of JWT validation errors",
	})

	ActivePeers = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wg_active_peers",
		Help: "Current number of active WireGuard peers",
	})
)
