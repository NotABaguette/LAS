package config

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

var identifierRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

var interfaceRoles = []string{"wan", "lan", "dmz", "mgmt", "tunnel"}
var tunnelTypes = []string{
	"tun", "wireguard", "openvpn", "ipsec", "ipsec-vti", "vti",
	"l2tp", "l2tp-ipsec", "pptp", "sstp", "pppoe",
	"gre", "gretap", "eoip", "ipip", "sit", "6to4", "ip6gre", "ip6tnl", "erspan", "vxlan", "l2tpv3",
	"openconnect", "anyconnect", "globalprotect", "pulse-secure", "fortigate-ssl", "fortinet-ssl",
	"vless", "vmess", "vless-xhttp", "xhttp", "sing-box", "xray",
	"tailscale", "zerotier", "custom",
}
var tunnelDirections = []string{"client", "server", "peer"}
var routeSetTypes = []string{"country", "application", "service", "custom"}
var wanGroupModes = []string{"weighted-ecmp", "failover", "active-backup"}
var bondModes = []string{"balance-rr", "active-backup", "balance-xor", "broadcast", "802.3ad", "balance-tlb", "balance-alb"}
var actionTypes = []string{"direct", "interface", "tunnel", "wan-group", "load-balance", "blackhole", "reject", "scan", "mirror"}
var protocols = []string{"tcp", "udp", "icmp", "icmpv6", "gre", "esp", "ah"}
var dnsServerEngines = []string{"", "dnsmasq", "unbound", "bind"}
var dhcpServerEngines = []string{"", "dnsmasq", "kea"}
var ntpEngines = []string{"", "chrony", "ntpd"}
var acmeEngines = []string{"", "certbot"}
var recordTypes = []string{"", "A", "AAAA", "CNAME", "TXT", "MX", "SRV", "PTR"}

func (c Config) Validate() error {
	if c.Version != CurrentVersion {
		return fmt.Errorf("unsupported config version %d", c.Version)
	}
	if c.UI.Listen == "" {
		return fmt.Errorf("ui.listen is required")
	}
	if c.Host.ConntrackMax < 0 {
		return fmt.Errorf("host.conntrackMax must be non-negative")
	}
	for _, cidr := range c.Host.ManagementCIDRs {
		if err := validateCIDR(cidr); err != nil {
			return fmt.Errorf("host.managementCIDRs %q: %w", cidr, err)
		}
	}

	ifaces := map[string]Interface{}
	for _, iface := range c.Interfaces {
		if err := validateInterface(iface); err != nil {
			return err
		}
		if _, exists := ifaces[iface.Name]; exists {
			return fmt.Errorf("duplicate interface %q", iface.Name)
		}
		ifaces[iface.Name] = iface
	}

	tunnels := map[string]Tunnel{}
	knownLinks := map[string]struct{}{}
	for name := range ifaces {
		knownLinks[name] = struct{}{}
	}
	for _, tunnel := range c.Tunnels {
		if err := validateTunnel(tunnel); err != nil {
			return err
		}
		if _, exists := tunnels[tunnel.ID]; exists {
			return fmt.Errorf("duplicate tunnel id %q", tunnel.ID)
		}
		tunnels[tunnel.ID] = tunnel
		if tunnel.InterfaceName != "" {
			knownLinks[tunnel.InterfaceName] = struct{}{}
		}
	}
	for _, vlan := range c.Platform.L2.VLANs {
		if vlan.Name != "" {
			knownLinks[vlan.Name] = struct{}{}
		}
	}
	for _, bridge := range c.Platform.L2.Bridges {
		if bridge.Name != "" {
			knownLinks[bridge.Name] = struct{}{}
		}
	}
	for _, bond := range c.Platform.L2.Bonds {
		if bond.Name != "" {
			knownLinks[bond.Name] = struct{}{}
		}
	}

	if err := validatePlatform(c.Platform, knownLinks); err != nil {
		return err
	}

	routeSets := map[string]RouteSet{}
	for _, routeSet := range c.Routing.Sets {
		if err := validateRouteSet(routeSet); err != nil {
			return err
		}
		if _, exists := routeSets[routeSet.ID]; exists {
			return fmt.Errorf("duplicate routing set id %q", routeSet.ID)
		}
		routeSets[routeSet.ID] = routeSet
	}

	wanGroups := map[string]WANGroup{}
	for _, group := range c.Routing.WANGroups {
		if err := validateWANGroup(group, knownLinks); err != nil {
			return err
		}
		if _, exists := wanGroups[group.ID]; exists {
			return fmt.Errorf("duplicate WAN group id %q", group.ID)
		}
		wanGroups[group.ID] = group
	}

	for _, route := range c.Routing.StaticRoutes {
		if err := validateStaticRoute(route, knownLinks); err != nil {
			return err
		}
	}
	for _, rule := range c.Routing.Rules {
		if err := validateRouteRule(rule, ifaces, knownLinks, tunnels, routeSets, wanGroups); err != nil {
			return err
		}
	}

	if err := validateServices(c.Services, knownLinks); err != nil {
		return err
	}
	return validateSecurity(c.Security, knownLinks)
}

func validateRouteSet(routeSet RouteSet) error {
	if !identifierRE.MatchString(routeSet.ID) {
		return fmt.Errorf("invalid route set id %q", routeSet.ID)
	}
	if !slices.Contains(routeSetTypes, routeSet.Type) {
		return fmt.Errorf("route set %s has unsupported type %q", routeSet.ID, routeSet.Type)
	}
	for _, cidr := range routeSet.CIDRs {
		if err := validateCIDR(cidr); err != nil {
			return fmt.Errorf("route set %s cidr %q: %w", routeSet.ID, cidr, err)
		}
	}
	return nil
}

func validateWANGroup(group WANGroup, knownLinks map[string]struct{}) error {
	if !identifierRE.MatchString(group.ID) {
		return fmt.Errorf("invalid WAN group id %q", group.ID)
	}
	if !slices.Contains(wanGroupModes, group.Mode) {
		return fmt.Errorf("WAN group %s has unsupported mode %q", group.ID, group.Mode)
	}
	if group.Mark < 0 || group.Mark > 0xfffffff {
		return fmt.Errorf("WAN group %s mark must fit in a Linux fwmark", group.ID)
	}
	if group.Table < 0 || group.Table > 252 {
		return fmt.Errorf("WAN group %s table must be 0-252", group.ID)
	}
	if len(group.Members) == 0 {
		return fmt.Errorf("WAN group %s requires at least one member", group.ID)
	}
	for _, member := range group.Members {
		if _, exists := knownLinks[member.Interface]; !exists {
			return fmt.Errorf("WAN group %s references unknown link %q", group.ID, member.Interface)
		}
		if member.Gateway != "" && net.ParseIP(member.Gateway) == nil {
			return fmt.Errorf("WAN group %s gateway %q is not an IP address", group.ID, member.Gateway)
		}
		if member.Weight < 0 {
			return fmt.Errorf("WAN group %s member %s weight must be non-negative", group.ID, member.Interface)
		}
		if member.Priority < 0 {
			return fmt.Errorf("WAN group %s member %s priority must be non-negative", group.ID, member.Interface)
		}
	}
	return nil
}

func validateInterface(iface Interface) error {
	if !identifierRE.MatchString(iface.Name) {
		return fmt.Errorf("invalid interface name %q", iface.Name)
	}
	if !slices.Contains(interfaceRoles, iface.Role) {
		return fmt.Errorf("interface %s has unsupported role %q", iface.Name, iface.Role)
	}
	if iface.MTU != 0 && (iface.MTU < 576 || iface.MTU > 9216) {
		return fmt.Errorf("interface %s mtu must be between 576 and 9216", iface.Name)
	}
	for _, address := range iface.Addresses {
		if address == "dhcp" {
			continue
		}
		if err := validateCIDR(address); err != nil {
			return fmt.Errorf("interface %s address %q: %w", iface.Name, address, err)
		}
	}
	if iface.Gateway != "" && net.ParseIP(iface.Gateway) == nil {
		return fmt.Errorf("interface %s gateway %q is not an IP address", iface.Name, iface.Gateway)
	}
	for _, dns := range iface.DNS {
		if net.ParseIP(dns) == nil {
			return fmt.Errorf("interface %s dns %q is not an IP address", iface.Name, dns)
		}
	}
	if iface.DHCPServer != nil {
		if net.ParseIP(iface.DHCPServer.RangeStart) == nil {
			return fmt.Errorf("interface %s dhcp rangeStart is not an IP address", iface.Name)
		}
		if net.ParseIP(iface.DHCPServer.RangeEnd) == nil {
			return fmt.Errorf("interface %s dhcp rangeEnd is not an IP address", iface.Name)
		}
		for _, dns := range iface.DHCPServer.DNS {
			if net.ParseIP(dns) == nil {
				return fmt.Errorf("interface %s dhcp dns %q is not an IP address", iface.Name, dns)
			}
		}
	}
	return nil
}

func validateTunnel(tunnel Tunnel) error {
	if !identifierRE.MatchString(tunnel.ID) {
		return fmt.Errorf("invalid tunnel id %q", tunnel.ID)
	}
	if !slices.Contains(tunnelTypes, tunnel.Type) {
		return fmt.Errorf("tunnel %s has unsupported type %q", tunnel.ID, tunnel.Type)
	}
	if tunnel.Direction != "" && !slices.Contains(tunnelDirections, tunnel.Direction) {
		return fmt.Errorf("tunnel %s has unsupported direction %q", tunnel.ID, tunnel.Direction)
	}
	if tunnel.InterfaceName != "" && !identifierRE.MatchString(tunnel.InterfaceName) {
		return fmt.Errorf("tunnel %s has invalid interface name %q", tunnel.ID, tunnel.InterfaceName)
	}
	if tunnel.Mark < 0 || tunnel.Mark > 0xfffffff {
		return fmt.Errorf("tunnel %s mark must fit in a Linux fwmark", tunnel.ID)
	}
	if tunnel.Table < 0 || tunnel.Table > 252 {
		return fmt.Errorf("tunnel %s table must be 0-252", tunnel.ID)
	}
	if tunnel.MTU != 0 && (tunnel.MTU < 576 || tunnel.MTU > 9216) {
		return fmt.Errorf("tunnel %s mtu must be between 576 and 9216", tunnel.ID)
	}
	for _, address := range tunnel.LocalAddresses {
		if err := validateCIDR(address); err != nil {
			return fmt.Errorf("tunnel %s local address %q: %w", tunnel.ID, address, err)
		}
	}
	for _, dns := range tunnel.DNS {
		if net.ParseIP(dns) == nil {
			return fmt.Errorf("tunnel %s dns %q is not an IP address", tunnel.ID, dns)
		}
	}
	return nil
}

func validateServices(services ServicesConfig, knownLinks map[string]struct{}) error {
	if !slices.Contains(dhcpServerEngines, services.DHCPServer.Engine) {
		return fmt.Errorf("dhcp server has unsupported engine %q", services.DHCPServer.Engine)
	}
	if !slices.Contains(dnsServerEngines, services.DNSServer.Engine) {
		return fmt.Errorf("dns server has unsupported engine %q", services.DNSServer.Engine)
	}
	if !slices.Contains(ntpEngines, services.NTPServer.Engine) {
		return fmt.Errorf("ntp server has unsupported engine %q", services.NTPServer.Engine)
	}
	for _, iface := range services.DHCPServer.Listen {
		if _, exists := knownLinks[iface]; !exists {
			return fmt.Errorf("dhcp server references unknown link %q", iface)
		}
	}
	for _, lease := range services.DHCPServer.StaticLeases {
		if lease.Hostname != "" && !validHostname(lease.Hostname) {
			return fmt.Errorf("dhcp static lease hostname %q is invalid", lease.Hostname)
		}
		if lease.MAC == "" {
			return fmt.Errorf("dhcp static lease for %s requires mac", lease.Hostname)
		}
		if lease.IP != "" && net.ParseIP(lease.IP) == nil {
			return fmt.Errorf("dhcp static lease %s ip %q is invalid", lease.Hostname, lease.IP)
		}
	}
	for _, iface := range services.DHCPClient.Interfaces {
		if _, exists := knownLinks[iface]; !exists {
			return fmt.Errorf("dhcp client references unknown link %q", iface)
		}
	}
	for _, iface := range services.DNSServer.Listen {
		if _, exists := knownLinks[iface]; !exists {
			return fmt.Errorf("dns server references unknown link %q", iface)
		}
	}
	for _, address := range services.DNSServer.ListenAddresses {
		if net.ParseIP(address) == nil {
			return fmt.Errorf("dns listen address %q is not an IP address", address)
		}
	}
	for _, resolver := range append(append([]string{}, services.DNSServer.Forwarders...), append(services.DNSClient.Resolvers, services.DNSClient.FallbackResolvers...)...) {
		if err := validateResolver(resolver); err != nil {
			return fmt.Errorf("dns resolver %q: %w", resolver, err)
		}
	}
	for _, zone := range services.DNSServer.ConditionalForwarders {
		if !validDomainName(zone.Domain) {
			return fmt.Errorf("dns conditional forwarder domain %q is invalid", zone.Domain)
		}
		for _, resolver := range zone.Upstreams {
			if err := validateResolver(resolver); err != nil {
				return fmt.Errorf("dns conditional forwarder %s resolver %q: %w", zone.Domain, resolver, err)
			}
		}
	}
	for _, record := range services.DNSServer.Records {
		if !validDomainName(record.Name) {
			return fmt.Errorf("dns record name %q is invalid", record.Name)
		}
		recordType := strings.ToUpper(record.Type)
		if !slices.Contains(recordTypes, recordType) {
			return fmt.Errorf("dns record %s has unsupported type %q", record.Name, record.Type)
		}
		if record.Value == "" {
			return fmt.Errorf("dns record %s requires value", record.Name)
		}
		if record.TTL < 0 {
			return fmt.Errorf("dns record %s ttl must be non-negative", record.Name)
		}
	}
	for _, override := range services.DNSServer.AddressOverrides {
		if !validDomainName(override.Domain) {
			return fmt.Errorf("dns override domain %q is invalid", override.Domain)
		}
		if net.ParseIP(override.Address) == nil {
			return fmt.Errorf("dns override %s address %q is invalid", override.Domain, override.Address)
		}
	}
	for _, iface := range services.NTPServer.Listen {
		if _, exists := knownLinks[iface]; !exists {
			return fmt.Errorf("ntp server references unknown link %q", iface)
		}
	}
	for _, cidr := range services.NTPServer.AllowCIDRs {
		if err := validateCIDR(cidr); err != nil {
			return fmt.Errorf("ntp allow cidr %q: %w", cidr, err)
		}
	}
	if services.NTPServer.LocalStratum < 0 || services.NTPServer.LocalStratum > 15 {
		return fmt.Errorf("ntp localStratum must be 0-15")
	}
	for _, iface := range services.MPLS.Interfaces {
		if _, exists := knownLinks[iface]; !exists {
			return fmt.Errorf("mpls references unknown link %q", iface)
		}
	}
	return validateCertificateStore(services.CertificateStore)
}

func validateStaticRoute(route StaticRoute, knownLinks map[string]struct{}) error {
	if err := validateCIDR(route.Destination); err != nil {
		return fmt.Errorf("static route destination %q: %w", route.Destination, err)
	}
	if route.Gateway == "" && route.Interface == "" {
		return fmt.Errorf("static route %s requires gateway or interface", route.Destination)
	}
	if route.Gateway != "" && net.ParseIP(route.Gateway) == nil {
		return fmt.Errorf("static route gateway %q is not an IP address", route.Gateway)
	}
	if route.Interface != "" {
		if _, exists := knownLinks[route.Interface]; !exists {
			return fmt.Errorf("static route references unknown link %q", route.Interface)
		}
	}
	if route.Table < 0 || route.Table > 252 {
		return fmt.Errorf("static route %s table must be 0-252", route.Destination)
	}
	if route.Metric < 0 {
		return fmt.Errorf("static route %s metric must be non-negative", route.Destination)
	}
	return nil
}

func validateRouteRule(rule RouteRule, ifaces map[string]Interface, knownLinks map[string]struct{}, tunnels map[string]Tunnel, routeSets map[string]RouteSet, wanGroups map[string]WANGroup) error {
	if !identifierRE.MatchString(rule.ID) {
		return fmt.Errorf("invalid rule id %q", rule.ID)
	}
	if rule.Priority < 1 || rule.Priority > 32765 {
		return fmt.Errorf("rule %s priority must be 1-32765", rule.ID)
	}
	if rule.Match.InputIface != "" {
		if _, exists := knownLinks[rule.Match.InputIface]; !exists {
			return fmt.Errorf("rule %s references unknown input link %q", rule.ID, rule.Match.InputIface)
		}
	}
	if rule.Match.OutputIface != "" {
		if _, exists := knownLinks[rule.Match.OutputIface]; !exists {
			return fmt.Errorf("rule %s references unknown output link %q", rule.ID, rule.Match.OutputIface)
		}
	}
	for _, cidr := range rule.Match.SourceCIDRs {
		if err := validateCIDR(cidr); err != nil {
			return fmt.Errorf("rule %s source cidr %q: %w", rule.ID, cidr, err)
		}
	}
	for _, cidr := range rule.Match.DestinationCIDRs {
		if err := validateCIDR(cidr); err != nil {
			return fmt.Errorf("rule %s destination cidr %q: %w", rule.ID, cidr, err)
		}
	}
	for _, portRange := range append(rule.Match.SourcePorts, rule.Match.DestinationPorts...) {
		if portRange.From < 1 || portRange.From > 65535 || portRange.To < 1 || portRange.To > 65535 || portRange.From > portRange.To {
			return fmt.Errorf("rule %s has invalid port range %d-%d", rule.ID, portRange.From, portRange.To)
		}
	}
	for _, proto := range rule.Match.Protocols {
		if !slices.Contains(protocols, proto) {
			return fmt.Errorf("rule %s has unsupported protocol %q", rule.ID, proto)
		}
	}
	for _, tunnelID := range rule.Match.TunnelIDs {
		if _, exists := tunnels[tunnelID]; !exists {
			return fmt.Errorf("rule %s references unknown match tunnel %q", rule.ID, tunnelID)
		}
	}
	for _, setID := range rule.Match.Sets {
		if _, exists := routeSets[setID]; !exists {
			return fmt.Errorf("rule %s references unknown route set %q", rule.ID, setID)
		}
	}
	if !slices.Contains(actionTypes, rule.Action.Type) {
		return fmt.Errorf("rule %s has unsupported action %q", rule.ID, rule.Action.Type)
	}
	if rule.Action.Type == "tunnel" {
		if _, exists := tunnels[rule.Action.Target]; !exists {
			return fmt.Errorf("rule %s targets unknown tunnel %q", rule.ID, rule.Action.Target)
		}
	}
	if rule.Action.Type == "interface" {
		if _, exists := knownLinks[rule.Action.Target]; !exists {
			return fmt.Errorf("rule %s targets unknown link %q", rule.ID, rule.Action.Target)
		}
	}
	if rule.Action.Type == "wan-group" || rule.Action.Type == "load-balance" {
		if _, exists := wanGroups[rule.Action.Target]; !exists {
			return fmt.Errorf("rule %s targets unknown WAN group %q", rule.ID, rule.Action.Target)
		}
	}
	if rule.Action.Mark < 0 || rule.Action.Mark > 0xfffffff {
		return fmt.Errorf("rule %s action mark must fit in a Linux fwmark", rule.ID)
	}
	if rule.Action.Table < 0 || rule.Action.Table > 252 {
		return fmt.Errorf("rule %s action table must be 0-252", rule.ID)
	}
	return nil
}

func validateSecurity(security SecurityConfig, knownLinks map[string]struct{}) error {
	for _, port := range security.ManagementPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("security management port %d is invalid", port)
		}
	}
	for _, forward := range security.PortForwards {
		if err := validatePortForward(forward, knownLinks); err != nil {
			return err
		}
	}
	for _, nat := range security.OneToOneNAT {
		if err := validateOneToOneNAT(nat, knownLinks); err != nil {
			return err
		}
	}
	for _, iface := range append(security.Antivirus.Interfaces, security.IPS.Interfaces...) {
		if _, exists := knownLinks[iface]; !exists {
			return fmt.Errorf("security references unknown link %q", iface)
		}
	}
	if security.Antivirus.MaxFileSizeMB < 0 {
		return fmt.Errorf("antivirus maxFileSizeMB must be non-negative")
	}
	if security.IPS.NFQueue < 0 || security.IPS.NFQueue > 65535 {
		return fmt.Errorf("ips nfqueue must be 0-65535")
	}
	for _, upstream := range security.DNSFiltering.Upstream {
		if net.ParseIP(upstream) == nil {
			return fmt.Errorf("dns filtering upstream %q is not an IP address", upstream)
		}
	}
	for _, iface := range append(security.CaptivePortal.Interfaces, security.UPnP.InternalIfaces...) {
		if _, exists := knownLinks[iface]; !exists {
			return fmt.Errorf("security service references unknown link %q", iface)
		}
	}
	if security.UPnP.ExternalIface != "" {
		if _, exists := knownLinks[security.UPnP.ExternalIface]; !exists {
			return fmt.Errorf("upnp external interface %q is unknown", security.UPnP.ExternalIface)
		}
	}
	return nil
}

func validatePlatform(platform PlatformConfig, knownLinks map[string]struct{}) error {
	if err := validateL2(platform.L2, knownLinks); err != nil {
		return err
	}
	if err := validateDynamicRouting(platform.Routing, knownLinks); err != nil {
		return err
	}
	if err := validateQoS(platform.QoS, knownLinks); err != nil {
		return err
	}
	if err := validateMonitoring(platform.Monitor, knownLinks); err != nil {
		return err
	}
	return validateAutomation(platform.Automation)
}

func validateL2(l2 L2Config, knownLinks map[string]struct{}) error {
	for _, vlan := range l2.VLANs {
		if !identifierRE.MatchString(vlan.Name) {
			return fmt.Errorf("invalid vlan name %q", vlan.Name)
		}
		if _, exists := knownLinks[vlan.Parent]; !exists {
			return fmt.Errorf("vlan %s references unknown parent link %q", vlan.Name, vlan.Parent)
		}
		if vlan.ID < 1 || vlan.ID > 4094 {
			return fmt.Errorf("vlan %s id must be 1-4094", vlan.Name)
		}
		for _, ip := range vlan.IPs {
			if err := validateCIDR(ip); err != nil {
				return fmt.Errorf("vlan %s ip %q: %w", vlan.Name, ip, err)
			}
		}
	}
	for _, bridge := range l2.Bridges {
		if !identifierRE.MatchString(bridge.Name) {
			return fmt.Errorf("invalid bridge name %q", bridge.Name)
		}
		for _, member := range bridge.Members {
			if _, exists := knownLinks[member]; !exists {
				return fmt.Errorf("bridge %s references unknown member %q", bridge.Name, member)
			}
		}
		for _, vlan := range bridge.VLANs {
			if vlan < 1 || vlan > 4094 {
				return fmt.Errorf("bridge %s vlan id must be 1-4094", bridge.Name)
			}
		}
	}
	for _, bond := range l2.Bonds {
		if !identifierRE.MatchString(bond.Name) {
			return fmt.Errorf("invalid bond name %q", bond.Name)
		}
		if bond.Mode != "" && !slices.Contains(bondModes, bond.Mode) {
			return fmt.Errorf("bond %s has unsupported mode %q", bond.Name, bond.Mode)
		}
		for _, member := range bond.Members {
			if _, exists := knownLinks[member]; !exists {
				return fmt.Errorf("bond %s references unknown member %q", bond.Name, member)
			}
		}
	}
	for _, vrrp := range l2.VRRP {
		if !identifierRE.MatchString(vrrp.ID) {
			return fmt.Errorf("invalid vrrp id %q", vrrp.ID)
		}
		if _, exists := knownLinks[vrrp.Interface]; !exists {
			return fmt.Errorf("vrrp %s references unknown link %q", vrrp.ID, vrrp.Interface)
		}
		if vrrp.VRID < 1 || vrrp.VRID > 255 {
			return fmt.Errorf("vrrp %s vrid must be 1-255", vrrp.ID)
		}
		for _, vip := range vrrp.VIPs {
			if err := validateCIDR(vip); err != nil {
				return fmt.Errorf("vrrp %s vip %q: %w", vrrp.ID, vip, err)
			}
		}
	}
	return nil
}

func validateDynamicRouting(routing DynamicRouting, knownLinks map[string]struct{}) error {
	for _, vrf := range routing.VRFs {
		if !identifierRE.MatchString(vrf.Name) {
			return fmt.Errorf("invalid vrf name %q", vrf.Name)
		}
		if vrf.Table < 1 || vrf.Table > 252 {
			return fmt.Errorf("vrf %s table must be 1-252", vrf.Name)
		}
		for _, iface := range vrf.Interfaces {
			if _, exists := knownLinks[iface]; !exists {
				return fmt.Errorf("vrf %s references unknown link %q", vrf.Name, iface)
			}
		}
	}
	if routing.BGP.Enabled && routing.BGP.ASN <= 0 {
		return fmt.Errorf("bgp asn must be positive")
	}
	for _, network := range append(append([]string{}, routing.BGP.Networks...), append(routing.OSPF.Networks, routing.RIP.Networks...)...) {
		if err := validateCIDR(network); err != nil {
			return fmt.Errorf("dynamic routing network %q: %w", network, err)
		}
	}
	for _, peer := range append(routing.BGP.Peers, routing.BFD.Peers...) {
		if peer.Address != "" && net.ParseIP(peer.Address) == nil {
			return fmt.Errorf("routing peer %s address %q is invalid", peer.Name, peer.Address)
		}
		if peer.Interface != "" {
			if _, exists := knownLinks[peer.Interface]; !exists {
				return fmt.Errorf("routing peer %s references unknown link %q", peer.Name, peer.Interface)
			}
		}
	}
	for _, routeMap := range routing.RouteMaps {
		if !identifierRE.MatchString(routeMap.Name) {
			return fmt.Errorf("invalid route-map name %q", routeMap.Name)
		}
		if routeMap.Sequence < 1 {
			return fmt.Errorf("route-map %s sequence must be positive", routeMap.Name)
		}
	}
	return nil
}

func validateQoS(qos QoSConfig, knownLinks map[string]struct{}) error {
	for _, queue := range qos.Queues {
		if !identifierRE.MatchString(queue.ID) {
			return fmt.Errorf("invalid qos queue id %q", queue.ID)
		}
		if _, exists := knownLinks[queue.Interface]; !exists {
			return fmt.Errorf("qos queue %s references unknown link %q", queue.ID, queue.Interface)
		}
	}
	return nil
}

func validateMonitoring(monitor MonitoringConfig, knownLinks map[string]struct{}) error {
	for _, iface := range monitor.NetFlow.Interfaces {
		if _, exists := knownLinks[iface]; !exists {
			return fmt.Errorf("netflow references unknown link %q", iface)
		}
	}
	if monitor.NetFlow.Port < 0 || monitor.NetFlow.Port > 65535 {
		return fmt.Errorf("netflow port must be 0-65535")
	}
	return nil
}

func validateAutomation(automation AutomationConfig) error {
	for _, job := range automation.Scheduler {
		if !identifierRE.MatchString(job.ID) {
			return fmt.Errorf("invalid scheduled job id %q", job.ID)
		}
		if job.Enabled && job.Schedule == "" {
			return fmt.Errorf("scheduled job %s requires schedule", job.ID)
		}
	}
	return nil
}

func validatePortForward(forward PortForward, knownLinks map[string]struct{}) error {
	if !identifierRE.MatchString(forward.ID) {
		return fmt.Errorf("invalid port forward id %q", forward.ID)
	}
	if !forward.Enabled {
		return nil
	}
	if forward.InputIface != "" {
		if _, exists := knownLinks[forward.InputIface]; !exists {
			return fmt.Errorf("port forward %s references unknown input link %q", forward.ID, forward.InputIface)
		}
	}
	if forward.ExternalPort < 1 || forward.ExternalPort > 65535 {
		return fmt.Errorf("port forward %s external port is invalid", forward.ID)
	}
	if forward.InternalPort < 1 || forward.InternalPort > 65535 {
		return fmt.Errorf("port forward %s internal port is invalid", forward.ID)
	}
	if net.ParseIP(forward.InternalIP) == nil {
		return fmt.Errorf("port forward %s internal IP %q is invalid", forward.ID, forward.InternalIP)
	}
	for _, proto := range forward.Protocols {
		if proto != "tcp" && proto != "udp" {
			return fmt.Errorf("port forward %s protocol %q must be tcp or udp", forward.ID, proto)
		}
	}
	for _, cidr := range forward.SourceCIDRs {
		if err := validateCIDR(cidr); err != nil {
			return fmt.Errorf("port forward %s source cidr %q: %w", forward.ID, cidr, err)
		}
	}
	return nil
}

func validateOneToOneNAT(nat OneToOneNAT, knownLinks map[string]struct{}) error {
	if !identifierRE.MatchString(nat.ID) {
		return fmt.Errorf("invalid 1:1 NAT id %q", nat.ID)
	}
	if !nat.Enabled {
		return nil
	}
	if err := validateCIDR(nat.InternalCIDR); err != nil {
		return fmt.Errorf("1:1 NAT %s internal cidr %q: %w", nat.ID, nat.InternalCIDR, err)
	}
	if err := validateCIDR(nat.ExternalCIDR); err != nil {
		return fmt.Errorf("1:1 NAT %s external cidr %q: %w", nat.ID, nat.ExternalCIDR, err)
	}
	for _, iface := range nat.Interfaces {
		if _, exists := knownLinks[iface]; !exists {
			return fmt.Errorf("1:1 NAT %s references unknown link %q", nat.ID, iface)
		}
	}
	return nil
}

func validateCertificateStore(store CertificateStore) error {
	if store.LetsEncrypt.Engine != "" && !slices.Contains(acmeEngines, store.LetsEncrypt.Engine) {
		return fmt.Errorf("letsencrypt has unsupported engine %q", store.LetsEncrypt.Engine)
	}
	ids := map[string]struct{}{}
	for _, authority := range store.Authorities {
		if !identifierRE.MatchString(authority.ID) {
			return fmt.Errorf("invalid certificate authority id %q", authority.ID)
		}
		if authority.SourceFile == "" && authority.PEM == "" {
			return fmt.Errorf("certificate authority %s requires sourceFile or pem", authority.ID)
		}
	}
	for _, cert := range store.Certificates {
		if !identifierRE.MatchString(cert.ID) {
			return fmt.Errorf("invalid certificate id %q", cert.ID)
		}
		if _, exists := ids[cert.ID]; exists {
			return fmt.Errorf("duplicate certificate id %q", cert.ID)
		}
		ids[cert.ID] = struct{}{}
		for _, domain := range cert.Domains {
			if !validDomainName(domain) {
				return fmt.Errorf("certificate %s domain %q is invalid", cert.ID, domain)
			}
		}
	}
	for _, cert := range store.LetsEncrypt.Certificates {
		if !identifierRE.MatchString(cert.ID) {
			return fmt.Errorf("invalid letsencrypt certificate id %q", cert.ID)
		}
		if len(cert.Domains) == 0 {
			return fmt.Errorf("letsencrypt certificate %s requires at least one domain", cert.ID)
		}
		for _, domain := range cert.Domains {
			if !validDomainName(domain) {
				return fmt.Errorf("letsencrypt certificate %s domain %q is invalid", cert.ID, domain)
			}
		}
		switch cert.Method {
		case "", "webroot", "standalone", "dns":
		default:
			return fmt.Errorf("letsencrypt certificate %s has unsupported method %q", cert.ID, cert.Method)
		}
	}
	if store.LetsEncrypt.Enabled && store.LetsEncrypt.Email == "" {
		return fmt.Errorf("letsencrypt email is required when ACME is enabled")
	}
	return nil
}

func validateCIDR(value string) error {
	if value == "" {
		return fmt.Errorf("empty CIDR")
	}
	if _, err := netip.ParsePrefix(value); err != nil {
		return err
	}
	return nil
}

func validateResolver(value string) error {
	if value == "" {
		return fmt.Errorf("empty resolver")
	}
	host := strings.TrimPrefix(value, "tls://")
	if strings.Contains(host, "#") {
		host = strings.SplitN(host, "#", 2)[0]
	}
	if strings.Contains(host, ":") {
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			host = strings.Trim(parsedHost, "[]")
		}
	}
	host = strings.Trim(host, "[]")
	if net.ParseIP(host) != nil || validDomainName(host) {
		return nil
	}
	return fmt.Errorf("expected IP address or DNS hostname")
}

func validHostname(value string) bool {
	return validDomainName(value)
}

func validDomainName(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	trimmed := strings.TrimSuffix(value, ".")
	if trimmed == "" {
		return false
	}
	for _, label := range strings.Split(trimmed, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '*' {
				continue
			}
			return false
		}
	}
	return true
}
