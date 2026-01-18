/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package validation

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/go-logr/logr"
)

// ValidateClusterDomain validates that the configured cluster domain matches the actual cluster configuration
func ValidateClusterDomain(logger logr.Logger) error {
	clusterDomain := os.Getenv("CLUSTER_DOMAIN")
	if clusterDomain == "" {
		clusterDomain = "cluster.local" // default
	}

	apiServer := os.Getenv("KUBERNETES_API_SERVER")
	if apiServer == "" {
		apiServer = "https://kubernetes.default.svc"
	}

	logger.Info("validating cluster domain configuration",
		"clusterDomain", clusterDomain,
		"apiServer", apiServer)

	// Validate cluster domain by checking if kubernetes service resolves
	if err := validateDNSResolution(logger, clusterDomain); err != nil {
		return err
	}

	logger.Info("cluster domain validation successful", "clusterDomain", clusterDomain)
	return nil
}

// validateDNSResolution validates that the cluster domain resolves correctly
func validateDNSResolution(logger logr.Logger, clusterDomain string) error {
	// Test DNS resolution for kubernetes.default.svc.<cluster-domain>
	testFQDN := fmt.Sprintf("kubernetes.default.svc.%s", clusterDomain)

	logger.Info("testing DNS resolution", "fqdn", testFQDN)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resolver := &net.Resolver{}
	addrs, err := resolver.LookupHost(ctx, testFQDN)
	if err != nil {
		return fmt.Errorf("DNS resolution failed for %s: %w. "+
			"This indicates the CLUSTER_DOMAIN environment variable (%s) does not match your cluster's actual domain. "+
			"To find your cluster domain, try: "+
			"1) kubectl get cm coredns -n kube-system -o yaml | grep 'cluster.local' (look for the domain) "+
			"2) kubectl run test --rm -i --image=busybox -- nslookup kubernetes.default.svc.cluster.local (try common domains)",
			testFQDN, err, clusterDomain)
	}

	if len(addrs) == 0 {
		return fmt.Errorf("DNS resolution returned no addresses for %s. "+
			"The CLUSTER_DOMAIN (%s) may be incorrect", testFQDN, clusterDomain)
	}

	logger.Info("DNS resolution successful", "fqdn", testFQDN, "addresses", addrs)
	return nil
}
