// Copyright 2023 The Cockroach Authors.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package install

import (
	"context"
	_ "embed"
	"fmt"
	"net"
	"strconv"
	"strings"
	"text/template"

	"github.com/alessio/shellescape"
	"github.com/cockroachdb/cockroach/pkg/roachprod/config"
	"github.com/cockroachdb/cockroach/pkg/roachprod/logger"
	"github.com/cockroachdb/cockroach/pkg/roachprod/vm"
	"github.com/cockroachdb/cockroach/pkg/util/syncutil"
	"github.com/cockroachdb/errors"
)

//go:embed scripts/open_ports.sh
var openPortsScript string

type ServiceType string

const (
	// ServiceTypeSQL is the service type for SQL services on a node.
	ServiceTypeSQL ServiceType = "sql"
	// ServiceTypeUI is the service type for UI services on a node.
	ServiceTypeUI ServiceType = "ui"
)

// SystemInterfaceName is the virtual cluster name to use to access the
// system interface. (a.k.a. "system tenant")
const SystemInterfaceName = "system"

type ServiceMode string

const (
	// ServiceModeShared is the service mode for services that are shared on a host process.
	ServiceModeShared ServiceMode = "shared"
	// ServiceModeExternal is the service mode for services that are run in a separate process.
	ServiceModeExternal ServiceMode = "external"
)

// SharedPriorityClass is the priority class used to indicate when a service is shared.
const SharedPriorityClass = 1000

// ServiceDesc describes a service running on a node.
type ServiceDesc struct {
	// VirtualClusterName is the name of the virtual cluster that owns
	// the service.
	VirtualClusterName string
	// ServiceType is the type of service.
	ServiceType ServiceType
	// ServiceMode is the mode of the service.
	ServiceMode ServiceMode
	// Node is the node the service is running on.
	Node Node
	// Instance is the instance number of the service.
	Instance int
	// Port is the port the service is running on.
	Port int
}

// NodeServiceMap is a convenience type for mapping services by service type for each node.
type NodeServiceMap map[Node]map[ServiceType]*ServiceDesc

// ServiceDescriptors is a convenience type for a slice of service descriptors.
type ServiceDescriptors []ServiceDesc

// ServicePredicate is a predicate function definition for filtering services.
type ServicePredicate func(ServiceDesc) bool

// localClusterPortCache is a workaround for local clusters to prevent multiple
// nodes from using the same port when searching for open ports.
var localClusterPortCache struct {
	mu        syncutil.Mutex
	startPort int
}

// serviceDNSName returns the DNS name for a service in the standard SRV form.
func serviceDNSName(
	dnsProvider vm.DNSProvider,
	virtualClusterName string,
	serviceType ServiceType,
	clusterName string,
) string {
	// An SRV record name must adhere to the standard form:
	// _service._proto.name.
	return fmt.Sprintf("_%s-%s._tcp.%s.%s", virtualClusterName, serviceType, clusterName, dnsProvider.Domain())
}

// serviceNameComponents returns the virtual cluster name and service
// type from a DNS name in the standard SRV form.
func serviceNameComponents(name string) (string, ServiceType, error) {
	nameParts := strings.Split(name, ".")
	if len(nameParts) < 2 {
		return "", "", errors.Newf("invalid DNS SRV name: %s", name)
	}

	serviceName := strings.TrimPrefix(nameParts[0], "_")
	splitIndex := strings.LastIndex(serviceName, "-")
	if splitIndex == -1 {
		return "", "", errors.Newf("invalid service name: %s", serviceName)
	}

	serviceTypeStr := serviceName[splitIndex+1:]
	var serviceType ServiceType
	switch {
	case serviceTypeStr == string(ServiceTypeSQL):
		serviceType = ServiceTypeSQL
	case serviceTypeStr == string(ServiceTypeUI):
		serviceType = ServiceTypeUI
	default:
		return "", "", errors.Newf("invalid service type: %s", serviceTypeStr)
	}
	return serviceName[:splitIndex], serviceType, nil
}

// DiscoverServices discovers services running on the given nodes.
// Services matching the virtual cluster name and service type are
// returned and can be filtered by passing predicates. It's possible
// that multiple services can be returned for the given parameters if
// instances of the same virtual cluster and type are running on any of the
// nodes.
func (c *SyncedCluster) DiscoverServices(
	ctx context.Context,
	virtualClusterName string,
	serviceType ServiceType,
	predicates ...ServicePredicate,
) (ServiceDescriptors, error) {
	// If no VC name is specified, use the system interface.
	if virtualClusterName == "" {
		virtualClusterName = SystemInterfaceName
	}
	mu := syncutil.Mutex{}
	records := make([]vm.DNSRecord, 0)
	err := vm.FanOutDNS(c.VMs, func(dnsProvider vm.DNSProvider, _ vm.List) error {
		service := fmt.Sprintf("%s-%s", virtualClusterName, string(serviceType))
		r, lookupErr := dnsProvider.LookupSRVRecords(ctx, service, "tcp", c.Name)
		if lookupErr != nil {
			return lookupErr
		}
		mu.Lock()
		defer mu.Unlock()
		records = append(records, r...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	descriptors, err := c.dnsRecordsToServiceDescriptors(records)
	if err != nil {
		return nil, err
	}
	return descriptors.Filter(predicates...), nil
}

// DiscoverService is a convenience method for discovering a single service. If
// no services are found, it returns a service descriptor with the default port
// for the service type.
func (c *SyncedCluster) DiscoverService(
	ctx context.Context,
	node Node,
	virtualClusterName string,
	serviceType ServiceType,
	sqlInstance int,
) (ServiceDesc, error) {
	services, err := c.DiscoverServices(
		ctx, virtualClusterName, serviceType, ServiceNodePredicate(node), ServiceInstancePredicate(sqlInstance),
	)
	if err != nil {
		return ServiceDesc{}, err
	}
	// If no services are found matching the criteria, attempt to discover a
	// service for the system interface, and assume the service is shared.
	if len(services) == 0 {
		services, err = c.DiscoverServices(
			ctx, SystemInterfaceName, serviceType, ServiceNodePredicate(node),
		)
		if err != nil {
			return ServiceDesc{}, err
		}
	}
	// Finally, fall back to the default ports if no services are found. This is
	// useful for backwards compatibility with clusters that were created before
	// the introduction of service discovery, or without a DNS provider.
	// TODO(Herko): Remove this once DNS support is fully functional.
	if len(services) == 0 {
		var port int
		switch serviceType {
		case ServiceTypeSQL:
			port = config.DefaultSQLPort
		case ServiceTypeUI:
			port = config.DefaultAdminUIPort
		default:
			return ServiceDesc{}, errors.Newf("invalid service type: %s", serviceType)
		}
		return ServiceDesc{
			ServiceType:        serviceType,
			ServiceMode:        ServiceModeShared,
			VirtualClusterName: virtualClusterName,
			Node:               node,
			Port:               port,
			Instance:           0,
		}, nil
	}
	return services[0], err
}

// MapServices discovers all service types for a given virtual cluster
// and instance and maps it by node and service type.
func (c *SyncedCluster) MapServices(
	ctx context.Context, virtualClusterName string, instance int,
) (NodeServiceMap, error) {
	nodeFilter := ServiceNodePredicate(c.Nodes...)
	instanceFilter := ServiceInstancePredicate(instance)
	sqlServices, err := c.DiscoverServices(ctx, virtualClusterName, ServiceTypeSQL, nodeFilter, instanceFilter)
	if err != nil {
		return nil, err
	}
	uiServices, err := c.DiscoverServices(ctx, virtualClusterName, ServiceTypeUI, nodeFilter, instanceFilter)
	if err != nil {
		return nil, err
	}
	serviceMap := make(NodeServiceMap)
	for _, node := range c.Nodes {
		serviceMap[node] = make(map[ServiceType]*ServiceDesc)
	}
	services := append(sqlServices, uiServices...)
	for _, service := range services {
		serviceMap[service.Node][service.ServiceType] = &service
	}
	return serviceMap, nil
}

// RegisterServices registers services with the DNS provider. This function is
// lenient and will not return an error if no DNS provider is available to
// register the service.
func (c *SyncedCluster) RegisterServices(ctx context.Context, services ServiceDescriptors) error {
	servicesByDNSProvider := make(map[string]ServiceDescriptors)
	for _, desc := range services {
		dnsProvider := c.VMs[desc.Node-1].DNSProvider
		if dnsProvider == "" {
			continue
		}
		servicesByDNSProvider[dnsProvider] = append(servicesByDNSProvider[dnsProvider], desc)
	}
	for dnsProviderName := range servicesByDNSProvider {
		return vm.ForDNSProvider(dnsProviderName, func(dnsProvider vm.DNSProvider) error {
			records := make([]vm.DNSRecord, 0)
			for _, desc := range servicesByDNSProvider[dnsProviderName] {
				name := serviceDNSName(dnsProvider, desc.VirtualClusterName, desc.ServiceType, c.Name)
				priority := 0
				if desc.ServiceMode == ServiceModeShared {
					priority = SharedPriorityClass
				}
				srvData := net.SRV{
					Target:   c.TargetDNSName(desc.Node),
					Port:     uint16(desc.Port),
					Priority: uint16(priority),
					Weight:   uint16(desc.Instance),
				}
				records = append(records, vm.CreateSRVRecord(name, srvData))
			}
			err := dnsProvider.CreateRecords(ctx, records...)
			if err != nil {
				return err
			}
			return nil
		})
	}
	return nil
}

// Filter returns a new ServiceDescriptors containing only the descriptors that
// match all the provided predicates.
func (d ServiceDescriptors) Filter(predicates ...ServicePredicate) ServiceDescriptors {
	filteredDescriptors := make(ServiceDescriptors, 0)
outer:
	for _, descriptor := range d {
		for _, filter := range predicates {
			if !filter(descriptor) {
				continue outer
			}
		}
		filteredDescriptors = append(filteredDescriptors, descriptor)
	}
	return filteredDescriptors
}

// ServiceNodePredicate returns a ServicePredicate that match on the given nodes.
func ServiceNodePredicate(nodes ...Node) ServicePredicate {
	nodeSet := make(map[Node]struct{})
	for _, node := range nodes {
		nodeSet[node] = struct{}{}
	}
	return func(descriptor ServiceDesc) bool {
		_, ok := nodeSet[descriptor.Node]
		return ok
	}
}

// ServiceInstancePredicate returns a ServicePredicate that match on the provided
// instance.
func ServiceInstancePredicate(instance int) ServicePredicate {
	return func(descriptor ServiceDesc) bool {
		return descriptor.Instance == instance
	}
}

// FindOpenPorts finds the requested number of open ports on the provided node.
func (c *SyncedCluster) FindOpenPorts(
	ctx context.Context, l *logger.Logger, node Node, startPort, count int,
) ([]int, error) {
	tpl, err := template.New("open_ports").
		Funcs(template.FuncMap{"shesc": func(i interface{}) string {
			return shellescape.Quote(fmt.Sprint(i))
		}}).
		Delims("#{", "#}").
		Parse(openPortsScript)
	if err != nil {
		return nil, err
	}

	var ports []int
	if c.IsLocal() {
		// For local clusters, we need to keep track of the ports we've already used
		// so that we don't use them again, when this function is called in
		// parallel. This does not protect against the case where concurrent calls
		// are made to roachprod to create local clusters.
		localClusterPortCache.mu.Lock()
		defer func() {
			nextPort := startPort
			if len(ports) > 0 {
				nextPort = ports[len(ports)-1]
			}
			localClusterPortCache.startPort = nextPort + 1
			localClusterPortCache.mu.Unlock()
		}()
		if localClusterPortCache.startPort > startPort {
			startPort = localClusterPortCache.startPort
		}
	}

	var buf strings.Builder
	if err := tpl.Execute(&buf, struct {
		StartPort int
		PortCount int
	}{
		StartPort: startPort,
		PortCount: count,
	}); err != nil {
		return nil, err
	}

	res, err := c.runCmdOnSingleNode(ctx, l, node, buf.String(), defaultCmdOpts("find-ports"))
	if err != nil {
		return nil, err
	}
	ports, err = stringToIntegers(strings.TrimSpace(res.CombinedOut))
	if err != nil {
		return nil, err
	}
	if len(ports) != count {
		return nil, errors.Errorf("expected %d ports, got %d", count, len(ports))
	}
	return ports, nil
}

// stringToIntegers converts a string of space-separated integers into a slice.
func stringToIntegers(str string) ([]int, error) {
	fields := strings.Fields(str)
	integers := make([]int, len(fields))
	for i, field := range fields {
		port, err := strconv.Atoi(field)
		if err != nil {
			return nil, err
		}
		integers[i] = port
	}
	return integers, nil
}

// dnsRecordsToServiceDescriptors converts a slice of DNS SRV records into a
// slice of ServiceDescriptors.
func (c *SyncedCluster) dnsRecordsToServiceDescriptors(
	records []vm.DNSRecord,
) (ServiceDescriptors, error) {
	// Map public DNS names to nodes.
	dnsNameToNode := make(map[string]Node)
	for idx := range c.VMs {
		node := Node(idx + 1)
		dnsNameToNode[c.TargetDNSName(node)] = node
	}
	// Parse SRV records into service descriptors.
	ports := make(ServiceDescriptors, 0)
	for _, record := range records {
		if record.Type != vm.SRV {
			continue
		}
		data, err := record.ParseSRVRecord()
		if err != nil {
			return nil, err
		}
		if _, ok := dnsNameToNode[data.Target]; !ok {
			continue
		}
		serviceMode := ServiceModeExternal
		if data.Priority >= SharedPriorityClass {
			serviceMode = ServiceModeShared
		}
		virtualClusterName, serviceType, err := serviceNameComponents(record.Name)
		if err != nil {
			return nil, err
		}
		ports = append(ports, ServiceDesc{
			VirtualClusterName: virtualClusterName,
			ServiceType:        serviceType,
			ServiceMode:        serviceMode,
			Port:               int(data.Port),
			Instance:           int(data.Weight),
			Node:               dnsNameToNode[data.Target],
		})
	}
	return ports, nil
}

func (c *SyncedCluster) TargetDNSName(node Node) string {
	cVM := c.VMs[node-1]
	postfix := ""
	if c.IsLocal() {
		// For local clusters the Public DNS is the same for all nodes, so we
		// need to add a postfix to make them unique.
		postfix = fmt.Sprintf("%d.", int(node))
	}
	// Targets always end with a period as per SRV record convention.
	return fmt.Sprintf("%s.%s", cVM.PublicDNS, postfix)
}
