// Copyright 2017 Istio Authors
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

// Functions related to translation from the control policies to Envoy config
// Policies apply to Envoy upstream clusters but may appear in the route section.

package envoy

import (
	meshconfig "istio.io/api/mesh/v1alpha1"
	routing "istio.io/api/routing/v1alpha1"
	routingv2 "istio.io/api/routing/v1alpha2"
	"istio.io/istio/pilot/model"
	"istio.io/istio/pilot/proxy"
)

func isDestinationExcludedForMTLS(serviceName string, mtlsExcludedServices []string) bool {
	hostname, _, _ := model.ParseServiceKey(serviceName)
	for _, serviceName := range mtlsExcludedServices {
		if hostname == serviceName {
			return true
		}
	}
	return false
}

// applyClusterPolicy assumes an outbound cluster and inserts custom configuration for the cluster
func applyClusterPolicy(cluster *Cluster,
	instances []*model.ServiceInstance,
	config model.IstioConfigStore,
	mesh *meshconfig.MeshConfig,
	accounts model.ServiceAccounts) {
	duration := protoDurationToMS(mesh.ConnectTimeout)
	cluster.ConnectTimeoutMs = duration

	// skip remaining policies for non mesh-local outbound clusters
	if !cluster.outbound {
		return
	}

	// Original DST cluster are used to route to services outside the mesh
	// where Istio auth does not apply.
	if cluster.Type != ClusterTypeOriginalDST {
		if !isDestinationExcludedForMTLS(cluster.ServiceName, mesh.MtlsExcludedServices) &&
			consolidateAuthPolicy(mesh, cluster.port.AuthenticationPolicy) == meshconfig.AuthenticationPolicy_MUTUAL_TLS {
			// apply auth policies
			ports := model.PortList{cluster.port}.GetNames()
			serviceAccounts := accounts.GetIstioServiceAccounts(cluster.hostname, ports)
			cluster.SSLContext = buildClusterSSLContext(proxy.AuthCertsPath, serviceAccounts)
		}
	}

	// apply destination policies
	policyConfig := config.Policy(instances, cluster.hostname, cluster.tags)

	if policyConfig == nil {

		// check for v1alpha2 destination rules
		policyConfigs, err := config.List(model.V1alpha2DestinationPolicy, model.NamespaceAll)
		if err != nil {
			for _, policy := range policyConfigs {
				destPolicy := policy.Spec.(*routingv2.DestinationRule)

				// TODO match service cluster name with DestinationRule.Name?

				// TODO perform DestinationRule.Subset check?

				if destPolicy.TrafficPolicy != nil {
					applyV2ClusterPolicy(destPolicy, cluster)
				}
			}
		}
		return
	}

	policy := policyConfig.Spec.(*routing.DestinationPolicy)

	// Load balancing policies do not apply for Original DST clusters
	// as the intent is to go directly to the instance.
	if policy.LoadBalancing != nil && cluster.Type != ClusterTypeOriginalDST {
		switch policy.LoadBalancing.GetName() {
		case routing.LoadBalancing_ROUND_ROBIN:
			cluster.LbType = LbTypeRoundRobin
		case routing.LoadBalancing_LEAST_CONN:
			cluster.LbType = LbTypeLeastRequest
		case routing.LoadBalancing_RANDOM:
			cluster.LbType = LbTypeRandom
		}
	}

	// Set up circuit breakers and outlier detection
	if policy.CircuitBreaker != nil && policy.CircuitBreaker.GetSimpleCb() != nil {
		cbconfig := policy.CircuitBreaker.GetSimpleCb()
		cluster.MaxRequestsPerConnection = int(cbconfig.HttpMaxRequestsPerConnection)

		// Envoy's circuit breaker is a combination of its circuit breaker (which is actually a bulk head)
		// outlier detection (which is per pod circuit breaker)
		cluster.CircuitBreaker = &CircuitBreaker{}
		if cbconfig.MaxConnections > 0 {
			cluster.CircuitBreaker.Default.MaxConnections = int(cbconfig.MaxConnections)
		}
		if cbconfig.HttpMaxRequests > 0 {
			cluster.CircuitBreaker.Default.MaxRequests = int(cbconfig.HttpMaxRequests)
		}
		if cbconfig.HttpMaxPendingRequests > 0 {
			cluster.CircuitBreaker.Default.MaxPendingRequests = int(cbconfig.HttpMaxPendingRequests)
		}
		//TODO: need to add max_retries as well. Currently it defaults to 3

		cluster.OutlierDetection = &OutlierDetection{}

		cluster.OutlierDetection.MaxEjectionPercent = 10
		if cbconfig.SleepWindow.Seconds > 0 {
			cluster.OutlierDetection.BaseEjectionTimeMS = protoDurationToMS(cbconfig.SleepWindow)
		}
		if cbconfig.HttpConsecutiveErrors > 0 {
			cluster.OutlierDetection.ConsecutiveErrors = int(cbconfig.HttpConsecutiveErrors)
		}
		if cbconfig.HttpDetectionInterval.Seconds > 0 {
			cluster.OutlierDetection.IntervalMS = protoDurationToMS(cbconfig.HttpDetectionInterval)
		}
		if cbconfig.HttpMaxEjectionPercent > 0 {
			cluster.OutlierDetection.MaxEjectionPercent = int(cbconfig.HttpMaxEjectionPercent)
		}
	}
}

//
func applyV2ClusterPolicy(destPolicy *routingv2.DestinationRule, cluster *Cluster) {
	if cluster.Type != ClusterTypeOriginalDST {
		switch destPolicy.TrafficPolicy.LbPolicy {
		case routingv2.TrafficPolicy_ROUND_ROBIN:
			cluster.LbType = LbTypeRoundRobin
		case routingv2.TrafficPolicy_LEAST_CONN:
			cluster.LbType = LbTypeLeastRequest
		case routingv2.TrafficPolicy_RANDOM, routingv2.TrafficPolicy_DEFAULT:
			cluster.LbType = LbTypeRandom
		}
	}

	if destPolicy.TrafficPolicy.ConnectionPool != nil {
		// Envoy's circuit breaker is a combination of its circuit breaker (which is actually a bulk head)
		// outlier detection (which is per pod circuit breaker)
		cluster.CircuitBreaker = &CircuitBreaker{}

		if destPolicy.TrafficPolicy.ConnectionPool.Http != nil {

			if destPolicy.TrafficPolicy.ConnectionPool.Http.MaxRequests > 0 {
				cluster.CircuitBreaker.Default.MaxRequests = int(destPolicy.TrafficPolicy.ConnectionPool.Http.MaxRequests)
			}
			if destPolicy.TrafficPolicy.ConnectionPool.Http.MaxPendingRequests > 0 {
				cluster.CircuitBreaker.Default.MaxPendingRequests = int(destPolicy.TrafficPolicy.ConnectionPool.Http.MaxPendingRequests)
			}

			if destPolicy.TrafficPolicy.ConnectionPool.Http.MaxRequestsPerConnection > 0 {
				cluster.MaxRequestsPerConnection = destPolicy.TrafficPolicy.ConnectionPool.Http.MaxRequestsPerConnection
			}
		}

		if destPolicy.TrafficPolicy.ConnectionPool.Tcp != nil {
			if destPolicy.TrafficPolicy.ConnectionPool.Tcp.MaxConnections > 0 {
				cluster.CircuitBreaker.Default.MaxConnections = int(destPolicy.TrafficPolicy.ConnectionPool.Tcp.MaxConnections)
			}

			if destPolicy.TrafficPolicy.ConnectionPool.Tcp.ConnectTimeout > 0 {
				cluster.ConnectTimeoutMs = protoDurationToMS(destPolicy.TrafficPolicy.ConnectionPool.Tcp.ConnectTimeout)
			}
		}
	}

	if destPolicy.TrafficPolicy.OutlierDetection != nil && destPolicy.TrafficPolicy.OutlierDetection.Http != nil{

		//TODO: need to add max_retries as well. Currently it defaults to 3

		cluster.OutlierDetection = &OutlierDetection{}

		cluster.OutlierDetection.MaxEjectionPercent = 10
		if destPolicy.TrafficPolicy.OutlierDetection.Http.BaseEjectionTime > 0 {
			cluster.OutlierDetection.BaseEjectionTimeMS = protoDurationToMS(destPolicy.TrafficPolicy.OutlierDetection.Http.BaseEjectionTime)
		}
		if destPolicy.TrafficPolicy.OutlierDetection.Http.ConsecutiveErrors > 0 {
			cluster.OutlierDetection.ConsecutiveErrors = int(destPolicy.TrafficPolicy.OutlierDetection.Http.ConsecutiveErrors)
		}
		if destPolicy.TrafficPolicy.OutlierDetection.Http.Interval > 0 {
			cluster.OutlierDetection.IntervalMS = protoDurationToMS(destPolicy.TrafficPolicy.OutlierDetection.Http.Interval)
		}
		if destPolicy.TrafficPolicy.OutlierDetection.Http.MaxEjectionPercent > 0 {
			cluster.OutlierDetection.MaxEjectionPercent = int(destPolicy.TrafficPolicy.OutlierDetection.Http.GetMaxEjectionPercent())
		}
	}
}