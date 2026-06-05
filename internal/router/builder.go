package router

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"debian-router/internal/config"
	"debian-router/internal/control"
)

func BuildPlan(cfg config.Config) (control.Plan, error) {
	if err := cfg.Validate(); err != nil {
		return control.Plan{}, err
	}

	var plan control.Plan
	addHostPlan(&plan, cfg)
	addInterfacePlan(&plan, cfg.Interfaces)
	addTunnelPlan(&plan, cfg.Tunnels)
	addRoutingPlan(&plan, cfg)
	addSecurityPlan(&plan, cfg)

	nft, warnings := BuildNftables(cfg)
	for _, warning := range warnings {
		plan.AddWarning(warning)
	}
	plan.AddWrite("render nftables policy", "/run/debian-router/nftables.conf", "0600", nft)
	plan.AddCommand("load nftables policy", "sh", "-c", "nft list table inet debian_router >/dev/null 2>&1 && nft delete table inet debian_router || true; nft -f /run/debian-router/nftables.conf")

	return plan, nil
}

func addHostPlan(plan *control.Plan, cfg config.Config) {
	if cfg.Host.Hostname != "" {
		plan.AddCommand("set hostname", "hostnamectl", "set-hostname", cfg.Host.Hostname)
	}
	if cfg.Host.EnableIPForward {
		plan.AddCommand("enable IPv4 forwarding", "sysctl", "-w", "net.ipv4.ip_forward=1")
		plan.AddCommand("enable IPv6 forwarding", "sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
	}
	if cfg.Host.ConntrackMax > 0 {
		plan.AddCommand("set conntrack capacity", "sysctl", "-w", "net.netfilter.nf_conntrack_max="+strconv.Itoa(cfg.Host.ConntrackMax))
	}
}

func addInterfacePlan(plan *control.Plan, interfaces []config.Interface) {
	for _, iface := range interfaces {
		if !iface.Enabled {
			plan.AddCommand("disable interface "+iface.Name, "ip", "link", "set", "dev", iface.Name, "down")
			continue
		}
		if iface.MTU > 0 {
			plan.AddCommand("set mtu for "+iface.Name, "ip", "link", "set", "dev", iface.Name, "mtu", strconv.Itoa(iface.MTU))
		}
		plan.AddCommand("bring up "+iface.Name, "ip", "link", "set", "dev", iface.Name, "up")
		for _, address := range iface.Addresses {
			if address == "dhcp" {
				plan.AddWarning("interface %s uses DHCP; install/configure systemd-networkd, NetworkManager, or dhclient outside the immediate apply plan", iface.Name)
				continue
			}
			plan.AddCommand("assign "+address+" to "+iface.Name, "ip", "address", "replace", address, "dev", iface.Name)
		}
		if iface.Gateway != "" {
			plan.AddCommand("set default route via "+iface.Name, "ip", "route", "replace", "default", "via", iface.Gateway, "dev", iface.Name)
		}
		if iface.DHCPServer != nil {
			plan.AddWarning("DHCP server for %s is modeled but requires dnsmasq/kea template activation in a future renderer", iface.Name)
		}
	}
}

func addTunnelPlan(plan *control.Plan, tunnels []config.Tunnel) {
	for _, tunnel := range tunnels {
		if !tunnel.Enabled {
			continue
		}
		if tunnel.InterfaceName == "" {
			plan.AddWarning("tunnel %s is enabled without interfaceName; routing rules can mark traffic but no device route will be created", tunnel.ID)
			continue
		}

		switch tunnel.Type {
		case "tun":
			plan.AddCommand("ensure TUN device "+tunnel.InterfaceName, "sh", "-c", fmt.Sprintf("ip link show dev %s >/dev/null 2>&1 || ip tuntap add dev %s mode tun", tunnel.InterfaceName, tunnel.InterfaceName))
		case "wireguard":
			configFile := tunnel.Credentials["configFile"]
			if configFile == "" {
				plan.AddWarning("wireguard tunnel %s has no credentials.configFile", tunnel.ID)
			} else {
				plan.AddCommand("ensure WireGuard interface "+tunnel.InterfaceName, "sh", "-c", fmt.Sprintf("ip link show dev %s >/dev/null 2>&1 || ip link add dev %s type wireguard", tunnel.InterfaceName, tunnel.InterfaceName))
				plan.AddCommand("load WireGuard config for "+tunnel.ID, "wg", "setconf", tunnel.InterfaceName, configFile)
			}
		case "gre", "ipip", "sit", "6to4", "ip6gre", "ip6tnl", "vti", "ipsec-vti":
			addIPTunnelPlan(plan, tunnel)
		case "gretap", "erspan":
			addIPLinkTunnelPlan(plan, tunnel)
		case "vxlan":
			addVXLANPlan(plan, tunnel)
		case "eoip":
			plan.AddWarning("EoIP tunnel %s is MikroTik GRE-based L2 tunneling; model it as gretap/VXLAN for Linux interoperability or provide an external EoIP-compatible service", tunnel.ID)
		case "l2tpv3":
			plan.AddWarning("L2TPv3 tunnel %s is modeled; full ip l2tp session/pseudowire rendering is TODO", tunnel.ID)
		case "openvpn":
			plan.AddWarning("openvpn tunnel %s should be managed by openvpn-client@%s.service and expose %s", tunnel.ID, tunnel.ID, tunnel.InterfaceName)
			plan.AddCommand("enable OpenVPN client "+tunnel.ID, "systemctl", "enable", "--now", "openvpn-client@"+tunnel.ID)
		case "ipsec", "l2tp", "l2tp-ipsec":
			plan.AddWarning("IPsec/L2TP tunnel %s requires strongSwan/xl2tpd secrets and peer profile files under /etc; full profile rendering is TODO", tunnel.ID)
			plan.AddCommand("enable strongSwan", "systemctl", "enable", "--now", "strongswan")
			if tunnel.Type == "l2tp" || tunnel.Type == "l2tp-ipsec" {
				plan.AddCommand("enable xl2tpd", "systemctl", "enable", "--now", "xl2tpd")
			}
		case "pptp", "sstp", "pppoe":
			service := tunnel.Options["service"]
			if service == "" {
				service = "ppp@" + tunnel.ID
			}
			plan.AddWarning("%s tunnel %s is PPP-backed; provide peer/secrets files and expose interface %s", tunnel.Type, tunnel.ID, tunnel.InterfaceName)
			plan.AddCommand("enable PPP tunnel service "+service, "systemctl", "enable", "--now", service)
		case "vless", "vmess", "vless-xhttp", "xhttp", "xray", "sing-box":
			engine := tunnel.Options["engine"]
			if engine == "" {
				engine = defaultProxyEngine(tunnel.Type)
			}
			configFile := tunnel.Credentials["configFile"]
			if configFile == "" {
				plan.AddWarning("%s tunnel %s has no credentials.configFile", tunnel.Type, tunnel.ID)
			}
			plan.AddWarning("%s tunnel %s is service-backed; ensure %s creates interface %s", tunnel.Type, tunnel.ID, engine, tunnel.InterfaceName)
			plan.AddCommand("enable "+engine+" service", "systemctl", "enable", "--now", engine)
		case "tailscale", "zerotier":
			service := tunnel.Type
			if tunnel.Type == "zerotier" {
				service = "zerotier-one"
			}
			plan.AddWarning("%s tunnel %s is managed by its own control plane; debian-routerd routes traffic into %s", tunnel.Type, tunnel.ID, tunnel.InterfaceName)
			plan.AddCommand("enable "+service+" service", "systemctl", "enable", "--now", service)
		case "custom":
			service := tunnel.Options["service"]
			if service == "" {
				plan.AddWarning("custom tunnel %s has no options.service", tunnel.ID)
			} else {
				plan.AddCommand("enable custom tunnel service "+service, "systemctl", "enable", "--now", service)
			}
		}

		if tunnel.MTU > 0 {
			plan.AddCommand("set mtu for "+tunnel.InterfaceName, "ip", "link", "set", "dev", tunnel.InterfaceName, "mtu", strconv.Itoa(tunnel.MTU))
		}
		plan.AddCommand("bring up tunnel "+tunnel.InterfaceName, "ip", "link", "set", "dev", tunnel.InterfaceName, "up")
		for _, address := range tunnel.LocalAddresses {
			plan.AddCommand("assign "+address+" to "+tunnel.InterfaceName, "ip", "address", "replace", address, "dev", tunnel.InterfaceName)
		}
		if tunnel.Table > 0 {
			plan.AddCommand("route tunnel table "+strconv.Itoa(tunnel.Table), "ip", "route", "replace", "default", "dev", tunnel.InterfaceName, "table", strconv.Itoa(tunnel.Table))
		}
	}
}

func addIPTunnelPlan(plan *control.Plan, tunnel config.Tunnel) {
	mode := tunnel.Type
	if mode == "6to4" {
		mode = "sit"
	}
	if mode == "ipsec-vti" {
		mode = "vti"
	}

	args := []string{"tunnel", "add", tunnel.InterfaceName, "mode", mode}
	for _, key := range []string{"local", "remote", "ttl", "key", "dev"} {
		if value := tunnel.Options[key]; value != "" {
			args = append(args, key, value)
		}
	}
	programArgs := args
	if mode == "ip6gre" || mode == "ip6tnl" {
		programArgs = append([]string{"-6"}, args...)
	}
	plan.AddCommand("ensure "+tunnel.Type+" tunnel "+tunnel.InterfaceName, "sh", "-c", fmt.Sprintf("ip link show dev %s >/dev/null 2>&1 || %s", tunnel.InterfaceName, joinCommand("ip", programArgs)))
}

func addIPLinkTunnelPlan(plan *control.Plan, tunnel config.Tunnel) {
	args := []string{"link", "add", tunnel.InterfaceName, "type", tunnel.Type}
	for _, key := range []string{"local", "remote", "key", "dev"} {
		if value := tunnel.Options[key]; value != "" {
			args = append(args, key, value)
		}
	}
	plan.AddCommand("ensure "+tunnel.Type+" link "+tunnel.InterfaceName, "sh", "-c", fmt.Sprintf("ip link show dev %s >/dev/null 2>&1 || %s", tunnel.InterfaceName, joinCommand("ip", args)))
}

func addVXLANPlan(plan *control.Plan, tunnel config.Tunnel) {
	args := []string{"link", "add", tunnel.InterfaceName, "type", "vxlan"}
	for _, key := range []string{"id", "remote", "local", "dev", "dstport"} {
		if value := tunnel.Options[key]; value != "" {
			args = append(args, key, value)
		}
	}
	if tunnel.Options["id"] == "" {
		plan.AddWarning("vxlan tunnel %s has no options.id", tunnel.ID)
	}
	plan.AddCommand("ensure vxlan link "+tunnel.InterfaceName, "sh", "-c", fmt.Sprintf("ip link show dev %s >/dev/null 2>&1 || %s", tunnel.InterfaceName, joinCommand("ip", args)))
}

func defaultProxyEngine(tunnelType string) string {
	if tunnelType == "sing-box" {
		return "sing-box"
	}
	return "xray"
}

func joinCommand(program string, args []string) string {
	parts := append([]string{program}, args...)
	for i, part := range parts {
		parts[i] = shellQuote(part)
	}
	return strings.Join(parts, " ")
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	if strings.IndexFunc(value, func(r rune) bool {
		return !(r >= 'A' && r <= 'Z') &&
			!(r >= 'a' && r <= 'z') &&
			!(r >= '0' && r <= '9') &&
			!strings.ContainsRune("@%_+=:,./-", r)
	}) == -1 {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func addRoutingPlan(plan *control.Plan, cfg config.Config) {
	for _, route := range cfg.Routing.StaticRoutes {
		args := []string{"route", "replace", route.Destination}
		if route.Gateway != "" {
			args = append(args, "via", route.Gateway)
		}
		if route.Interface != "" {
			args = append(args, "dev", route.Interface)
		}
		if route.Table > 0 {
			args = append(args, "table", strconv.Itoa(route.Table))
		}
		if route.Metric > 0 {
			args = append(args, "metric", strconv.Itoa(route.Metric))
		}
		plan.AddCommand("add static route "+route.Destination, "ip", args...)
	}

	rules := append([]config.RouteRule{}, cfg.Routing.Rules...)
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		mark, table := resolveRuleRoute(rule, cfg.Tunnels)
		if mark == 0 || table == 0 {
			continue
		}
		cmd := fmt.Sprintf("ip rule del priority %d 2>/dev/null || true; ip rule add priority %d fwmark %d table %d", rule.Priority, rule.Priority, mark, table)
		plan.AddCommand("install policy rule "+rule.ID, "sh", "-c", cmd)
	}
}

func addSecurityPlan(plan *control.Plan, cfg config.Config) {
	security := cfg.Security
	if security.IPS.Enabled {
		switch security.IPS.Engine {
		case "", "suricata":
			content := renderSuricataConfig(security.IPS)
			plan.AddWrite("render Suricata interface config", "/etc/debian-router/suricata.yaml", "0600", content)
			plan.AddCommand("enable Suricata IPS", "systemctl", "enable", "--now", "suricata")
		default:
			plan.AddWarning("unsupported IPS engine %q; expected suricata", security.IPS.Engine)
		}
	}
	if security.Antivirus.Enabled {
		plan.AddWrite("render ClamAV router profile", "/etc/debian-router/clamav-router.conf", "0600", renderClamAVConfig(security.Antivirus))
		plan.AddCommand("enable ClamAV daemon", "systemctl", "enable", "--now", "clamav-daemon")
		plan.AddWarning("antivirus mode %s requires a proxy/ICAP integration point; encrypted pass-through traffic cannot be scanned transparently", security.Antivirus.Mode)
	}
	if security.DNSFiltering.Enabled {
		plan.AddWrite("render dnsmasq filtering profile", "/etc/debian-router/dnsmasq-router.conf", "0600", renderDNSMasqConfig(security.DNSFiltering))
		plan.AddCommand("enable dnsmasq", "systemctl", "enable", "--now", "dnsmasq")
	}
}

func resolveRuleRoute(rule config.RouteRule, tunnels []config.Tunnel) (int, int) {
	mark := rule.Action.Mark
	table := rule.Action.Table
	if rule.Action.Type == "tunnel" {
		for _, tunnel := range tunnels {
			if tunnel.ID == rule.Action.Target {
				if mark == 0 {
					mark = tunnel.Mark
				}
				if table == 0 {
					table = tunnel.Table
				}
				break
			}
		}
	}
	return mark, table
}

func renderSuricataConfig(ips config.IPSConfig) string {
	var b strings.Builder
	b.WriteString("%YAML 1.1\n---\n")
	b.WriteString("vars:\n  address-groups:\n    HOME_NET: \"[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]\"\n")
	if ips.Mode == "nfqueue" {
		b.WriteString("nfq:\n")
		b.WriteString(fmt.Sprintf("  mode: accept\n  queues:\n    - id: %d\n", ips.NFQueue))
	} else {
		b.WriteString("af-packet:\n")
		for _, iface := range ips.Interfaces {
			b.WriteString(fmt.Sprintf("  - interface: %s\n    cluster-id: 99\n    cluster-type: cluster_flow\n    defrag: yes\n", iface))
		}
	}
	return b.String()
}

func renderClamAVConfig(av config.AntivirusConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by debian-routerd. Use this profile from an ICAP/proxy integration.\n")
	b.WriteString(fmt.Sprintf("mode=%s\n", av.Mode))
	b.WriteString(fmt.Sprintf("max_file_size_mb=%d\n", av.MaxFileSizeMB))
	b.WriteString(fmt.Sprintf("quarantine_dir=%s\n", av.QuarantineDir))
	b.WriteString("interfaces=" + strings.Join(av.Interfaces, ",") + "\n")
	return b.String()
}

func renderDNSMasqConfig(dns config.DNSFilteringConf) string {
	var b strings.Builder
	b.WriteString("# Managed by debian-routerd.\n")
	b.WriteString("domain-needed\nbogus-priv\n")
	for _, upstream := range dns.Upstream {
		b.WriteString("server=" + upstream + "\n")
	}
	for _, blocklist := range dns.Blocklists {
		b.WriteString("# blocklist=" + blocklist + "\n")
	}
	return b.String()
}
