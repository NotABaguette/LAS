package config

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
)

var identifierRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

var interfaceRoles = []string{"wan", "lan", "dmz", "mgmt", "tunnel"}
var tunnelTypes = []string{
	"tun", "wireguard", "openvpn", "ipsec", "ipsec-vti", "vti",
	"l2tp", "l2tp-ipsec", "pptp", "sstp", "pppoe",
	"gre", "gretap", "eoip", "ipip", "sit", "6to4", "ip6gre", "ip6tnl", "erspan", "vxlan", "l2tpv3",
	"vless", "vmess", "vless-xhttp", "xhttp", "sing-box", "xray",
	"tailscale", "zerotier", "custom",
}
var actionTypes = []string{"direct", "interface", "tunnel", "blackhole", "reject", "scan", "mirror"}
var protocols = []string{"tcp", "udp", "icmp", "icmpv6", "gre", "esp", "ah"}

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

	for _, route := range c.Routing.StaticRoutes {
		if err := validateStaticRoute(route, knownLinks); err != nil {
			return err
		}
	}
	for _, rule := range c.Routing.Rules {
		if err := validateRouteRule(rule, ifaces, knownLinks, tunnels); err != nil {
			return err
		}
	}

	return validateSecurity(c.Security, ifaces)
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

func validateRouteRule(rule RouteRule, ifaces map[string]Interface, knownLinks map[string]struct{}, tunnels map[string]Tunnel) error {
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
	if !slices.Contains(actionTypes, rule.Action.Type) {
		return fmt.Errorf("rule %s has unsupported action %q", rule.ID, rule.Action.Type)
	}
	if rule.Action.Type == "tunnel" {
		if _, exists := tunnels[rule.Action.Target]; !exists {
			return fmt.Errorf("rule %s targets unknown tunnel %q", rule.ID, rule.Action.Target)
		}
	}
	if rule.Action.Type == "interface" {
		if _, exists := ifaces[rule.Action.Target]; !exists {
			return fmt.Errorf("rule %s targets unknown interface %q", rule.ID, rule.Action.Target)
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

func validateSecurity(security SecurityConfig, ifaces map[string]Interface) error {
	for _, port := range security.ManagementPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("security management port %d is invalid", port)
		}
	}
	for _, iface := range append(security.Antivirus.Interfaces, security.IPS.Interfaces...) {
		if _, exists := ifaces[iface]; !exists {
			return fmt.Errorf("security references unknown interface %q", iface)
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
