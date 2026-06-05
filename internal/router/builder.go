package router

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/NotABaguette/LAS/internal/config"
	"github.com/NotABaguette/LAS/internal/control"
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
	addServicesPlan(&plan, cfg)
	addPlatformPlan(&plan, cfg)
	addSecurityPlan(&plan, cfg)

	nft, warnings := BuildNftables(cfg)
	for _, warning := range warnings {
		plan.AddWarning(warning)
	}
	plan.AddWrite("render nftables policy", "/run/las/nftables.conf", "0600", nft)
	plan.AddCommand("load nftables policy", "sh", "-c", "nft list table inet las_router >/dev/null 2>&1 && nft delete table inet las_router || true; nft -f /run/las/nftables.conf")

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
			plan.AddWarning("%s tunnel %s is managed by its own control plane; lasd routes traffic into %s", tunnel.Type, tunnel.ID, tunnel.InterfaceName)
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
	for _, group := range cfg.Routing.WANGroups {
		if !group.Enabled {
			continue
		}
		addWANGroupPlan(plan, group)
	}

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
		mark, table := resolveRuleRouteWithGroups(rule, cfg.Tunnels, cfg.Routing.WANGroups)
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
			plan.AddWrite("render Suricata interface config", "/etc/las/suricata.yaml", "0600", content)
			plan.AddCommand("enable Suricata IPS", "systemctl", "enable", "--now", "suricata")
		default:
			plan.AddWarning("unsupported IPS engine %q; expected suricata", security.IPS.Engine)
		}
	}
	if security.Antivirus.Enabled {
		plan.AddWrite("render ClamAV router profile", "/etc/las/clamav-router.conf", "0600", renderClamAVConfig(security.Antivirus))
		plan.AddCommand("enable ClamAV daemon", "systemctl", "enable", "--now", "clamav-daemon")
		plan.AddWarning("antivirus mode %s requires a proxy/ICAP integration point; encrypted pass-through traffic cannot be scanned transparently", security.Antivirus.Mode)
	}
	if security.DNSFiltering.Enabled {
		plan.AddWrite("render dnsmasq filtering profile", "/etc/las/dnsmasq-router.conf", "0600", renderDNSMasqConfig(security.DNSFiltering))
		plan.AddCommand("enable dnsmasq", "systemctl", "enable", "--now", "dnsmasq")
	}
	if security.ThreatFeeds.Enabled {
		plan.AddWrite("render threat feed sources", "/etc/las/threat-feeds.conf", "0600", strings.Join(security.ThreatFeeds.SourceURLs, "\n")+"\n")
		plan.AddWarning("threat feeds are modeled; feed downloader to nft sets and Suricata rules is enabled as an integration hook")
	}
	if security.CaptivePortal.Enabled {
		plan.AddWrite("render captive portal profile", "/etc/las/captive-portal.conf", "0600", renderCaptivePortalConfig(security.CaptivePortal))
		plan.AddCommand("enable captive portal engine", "systemctl", "enable", "--now", captivePortalService(security.CaptivePortal.Engine))
	}
	if security.RADIUS.Enabled {
		plan.AddWrite("render RADIUS client profile", "/etc/las/radius.conf", "0600", renderRADIUSConfig(security.RADIUS))
		plan.AddCommand("enable FreeRADIUS", "systemctl", "enable", "--now", "freeradius")
	}
	if security.UPnP.Enabled {
		plan.AddWrite("render miniupnpd config", "/etc/miniupnpd/miniupnpd.conf", "0600", renderUPnPConfig(security.UPnP))
		plan.AddCommand("enable miniupnpd", "systemctl", "enable", "--now", "miniupnpd")
	}
}

func addServicesPlan(plan *control.Plan, cfg config.Config) {
	services := cfg.Services
	if services.DHCPServer.Enabled || services.DNSServer.Enabled {
		plan.AddWrite("render dnsmasq service profile", "/etc/las/dnsmasq-services.conf", "0600", renderDNSDHCPConfig(cfg))
		plan.AddCommand("enable dnsmasq for DHCP/DNS", "systemctl", "enable", "--now", "dnsmasq")
		plan.AddWarning("dnsmasq renderer is a baseline service profile; full per-interface DHCP reservations, options, and DNS views are TODO")
	}
	if services.DHCPClient.Enabled {
		plan.AddWarning("DHCP client is modeled on interfaces %s; use systemd-networkd, NetworkManager, or dhclient renderer TODO", strings.Join(services.DHCPClient.Interfaces, ","))
	}
	if services.NTPServer.Enabled || services.NTPClient.Enabled {
		plan.AddWrite("render chrony profile", "/etc/las/chrony.conf", "0600", renderChronyConfig(services.NTPServer, services.NTPClient))
		plan.AddCommand("enable chrony", "systemctl", "enable", "--now", "chrony")
	}
	if services.MPLS.Enabled {
		plan.AddWarning("MPLS is modeled for links %s; enable kernel MPLS modules and complete FRR LDP/VPLS renderer TODO", strings.Join(services.MPLS.Interfaces, ","))
		plan.AddCommand("enable FRR for MPLS/LDP", "systemctl", "enable", "--now", "frr")
	}
}

func addPlatformPlan(plan *control.Plan, cfg config.Config) {
	addL2Plan(plan, cfg.Platform.L2)
	addDynamicRoutingPlan(plan, cfg.Platform.Routing, cfg.Services.MPLS)
	addQoSPlan(plan, cfg.Platform.QoS)
	addMonitoringPlan(plan, cfg.Platform.Monitor)
	addAutomationPlan(plan, cfg.Platform.Automation)
	if cfg.Platform.Access.AuthEnabled {
		plan.AddWrite("render LAS access policy", "/etc/las/access.json", "0600", renderAccessConfig(cfg.Platform.Access))
		plan.AddWarning("access/RBAC is modeled and written to /etc/las/access.json; enforcing it in the HTTP API/session layer is the next hardening step")
	}
}

func addL2Plan(plan *control.Plan, l2 config.L2Config) {
	for _, bond := range l2.Bonds {
		mode := bond.Mode
		if mode == "" {
			mode = "802.3ad"
		}
		plan.AddCommand("load bonding module", "modprobe", "bonding")
		plan.AddCommand("ensure bond "+bond.Name, "sh", "-c", fmt.Sprintf("ip link show dev %s >/dev/null 2>&1 || ip link add %s type bond mode %s", bond.Name, bond.Name, mode))
		if bond.MTU > 0 {
			plan.AddCommand("set mtu for bond "+bond.Name, "ip", "link", "set", "dev", bond.Name, "mtu", strconv.Itoa(bond.MTU))
		}
		for _, member := range bond.Members {
			plan.AddCommand("enslave "+member+" to "+bond.Name, "sh", "-c", fmt.Sprintf("ip link set %s down; ip link set %s master %s; ip link set %s up", member, member, bond.Name, member))
		}
		plan.AddCommand("bring up bond "+bond.Name, "ip", "link", "set", "dev", bond.Name, "up")
	}
	for _, bridge := range l2.Bridges {
		plan.AddCommand("ensure bridge "+bridge.Name, "sh", "-c", fmt.Sprintf("ip link show dev %s >/dev/null 2>&1 || ip link add name %s type bridge", bridge.Name, bridge.Name))
		stp := "0"
		if bridge.STP {
			stp = "1"
		}
		plan.AddCommand("set bridge stp "+bridge.Name, "ip", "link", "set", "dev", bridge.Name, "type", "bridge", "stp_state", stp)
		if bridge.VLANAware {
			plan.AddCommand("enable vlan-aware bridge "+bridge.Name, "ip", "link", "set", "dev", bridge.Name, "type", "bridge", "vlan_filtering", "1")
		}
		for _, member := range bridge.Members {
			plan.AddCommand("add bridge member "+member, "sh", "-c", fmt.Sprintf("ip link set %s master %s; ip link set %s up", member, bridge.Name, member))
		}
		plan.AddCommand("bring up bridge "+bridge.Name, "ip", "link", "set", "dev", bridge.Name, "up")
	}
	for _, vlan := range l2.VLANs {
		plan.AddCommand("ensure vlan "+vlan.Name, "sh", "-c", fmt.Sprintf("ip link show dev %s >/dev/null 2>&1 || ip link add link %s name %s type vlan id %d", vlan.Name, vlan.Parent, vlan.Name, vlan.ID))
		if vlan.MTU > 0 {
			plan.AddCommand("set mtu for vlan "+vlan.Name, "ip", "link", "set", "dev", vlan.Name, "mtu", strconv.Itoa(vlan.MTU))
		}
		for _, ip := range vlan.IPs {
			plan.AddCommand("assign "+ip+" to "+vlan.Name, "ip", "address", "replace", ip, "dev", vlan.Name)
		}
		plan.AddCommand("bring up vlan "+vlan.Name, "ip", "link", "set", "dev", vlan.Name, "up")
	}
	if len(l2.VRRP) > 0 {
		plan.AddWrite("render keepalived VRRP config", "/etc/keepalived/keepalived.conf", "0600", renderKeepalived(l2.VRRP))
		plan.AddCommand("enable keepalived", "systemctl", "enable", "--now", "keepalived")
	}
}

func addDynamicRoutingPlan(plan *control.Plan, routing config.DynamicRouting, mpls config.MPLSConfig) {
	for _, vrf := range routing.VRFs {
		plan.AddCommand("ensure vrf "+vrf.Name, "sh", "-c", fmt.Sprintf("ip link show dev %s >/dev/null 2>&1 || ip link add %s type vrf table %d", vrf.Name, vrf.Name, vrf.Table))
		plan.AddCommand("bring up vrf "+vrf.Name, "ip", "link", "set", "dev", vrf.Name, "up")
		for _, iface := range vrf.Interfaces {
			plan.AddCommand("attach "+iface+" to vrf "+vrf.Name, "ip", "link", "set", "dev", iface, "master", vrf.Name)
		}
	}
	if routing.BGP.Enabled || routing.OSPF.Enabled || routing.RIP.Enabled || routing.BFD.Enabled || mpls.Enabled || len(routing.RouteMaps) > 0 {
		plan.AddWrite("render FRR routing config", "/etc/frr/frr.conf", "0600", renderFRRConfig(routing, mpls))
		plan.AddWrite("render FRR daemon toggles", "/etc/frr/daemons", "0644", renderFRRDaemons(routing, mpls))
		plan.AddCommand("enable FRR routing stack", "systemctl", "enable", "--now", "frr")
	}
	if mpls.Enabled {
		plan.AddCommand("load MPLS modules", "sh", "-c", "modprobe mpls_router || true; modprobe mpls_gso || true")
		for _, iface := range mpls.Interfaces {
			plan.AddCommand("enable MPLS input on "+iface, "sysctl", "-w", "net.mpls.conf."+iface+".input=1")
		}
	}
}

func addQoSPlan(plan *control.Plan, qos config.QoSConfig) {
	if !qos.Enabled {
		return
	}
	for _, queue := range qos.Queues {
		kind := queue.Kind
		if kind == "" {
			kind = "cake"
		}
		switch kind {
		case "cake":
			args := []string{"qdisc", "replace", "dev", queue.Interface, "root", "cake"}
			if queue.Rate != "" {
				args = append(args, "bandwidth", queue.Rate)
			}
			plan.AddCommand("install CAKE queue "+queue.ID, "tc", args...)
		case "fq_codel":
			plan.AddCommand("install FQ-CoDel queue "+queue.ID, "tc", "qdisc", "replace", "dev", queue.Interface, "root", "fq_codel")
		default:
			plan.AddWarning("qos queue %s kind %s is modeled but needs a renderer", queue.ID, kind)
		}
	}
}

func addMonitoringPlan(plan *control.Plan, monitor config.MonitoringConfig) {
	if monitor.SNMP.Enabled {
		plan.AddWrite("render snmpd config", "/etc/snmp/snmpd.conf", "0600", renderSNMPConfig(monitor.SNMP))
		plan.AddCommand("enable snmpd", "systemctl", "enable", "--now", "snmpd")
	}
	if monitor.NetFlow.Enabled {
		plan.AddWrite("render softflowd defaults", "/etc/default/softflowd", "0644", renderSoftflowdConfig(monitor.NetFlow))
		plan.AddCommand("enable softflowd", "systemctl", "enable", "--now", "softflowd")
	}
	if monitor.TrafficGraphs.Enabled {
		plan.AddCommand("enable node exporter", "systemctl", "enable", "--now", "prometheus-node-exporter")
		plan.AddWarning("traffic graph UI is modeled via node exporter; dashboard rendering is TODO")
	}
}

func addAutomationPlan(plan *control.Plan, automation config.AutomationConfig) {
	if automation.AuditLog.Enabled {
		path := automation.AuditLog.Path
		if path == "" {
			path = "/var/log/las/audit.log"
		}
		plan.AddCommand("ensure audit log", "sh", "-c", fmt.Sprintf("install -d -m 0750 %s; touch %s; chmod 0600 %s", shellQuote(filepathDir(path)), shellQuote(path), shellQuote(path)))
	}
	if automation.RollbackWatchdog.Enabled {
		plan.AddWrite("render rollback watchdog", "/usr/local/sbin/las-rollback-watchdog", "0755", renderRollbackWatchdog(automation.RollbackWatchdog))
		plan.AddWrite("render rollback watchdog service", "/etc/systemd/system/las-rollback-watchdog.service", "0644", "[Unit]\nDescription=LAS rollback watchdog\nAfter=network-online.target\n\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/las-rollback-watchdog\n")
	}
	for _, job := range automation.Scheduler {
		if !job.Enabled {
			continue
		}
		service := fmt.Sprintf("[Unit]\nDescription=LAS scheduled job %s\n\n[Service]\nType=oneshot\nExecStart=/bin/sh -c %s\n", job.ID, shellQuote(job.Command))
		timer := fmt.Sprintf("[Unit]\nDescription=LAS scheduled job timer %s\n\n[Timer]\nOnCalendar=%s\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n", job.ID, job.Schedule)
		plan.AddWrite("render scheduled job service "+job.ID, "/etc/systemd/system/las-job-"+job.ID+".service", "0644", service)
		plan.AddWrite("render scheduled job timer "+job.ID, "/etc/systemd/system/las-job-"+job.ID+".timer", "0644", timer)
		plan.AddCommand("enable scheduled job "+job.ID, "systemctl", "enable", "--now", "las-job-"+job.ID+".timer")
	}
	if automation.Backup.Enabled {
		plan.AddWrite("render backup script", "/usr/local/sbin/las-backup", "0755", renderBackupScript(automation.Backup))
		if automation.Backup.Schedule != "" {
			plan.AddWrite("render backup timer", "/etc/systemd/system/las-backup.timer", "0644", fmt.Sprintf("[Unit]\nDescription=LAS backup timer\n\n[Timer]\nOnCalendar=%s\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n", automation.Backup.Schedule))
			plan.AddWrite("render backup service", "/etc/systemd/system/las-backup.service", "0644", "[Unit]\nDescription=LAS backup\n\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/las-backup\n")
			plan.AddCommand("enable LAS backup timer", "systemctl", "enable", "--now", "las-backup.timer")
		}
	}
}

func renderDNSDHCPConfig(cfg config.Config) string {
	var b strings.Builder
	b.WriteString("# Managed by LAS.\n")
	if cfg.Services.DNSServer.Enabled {
		b.WriteString("domain-needed\nbogus-priv\n")
		for _, iface := range cfg.Services.DNSServer.Listen {
			b.WriteString("interface=" + iface + "\n")
		}
		for _, forwarder := range cfg.Services.DNSServer.Forwarders {
			b.WriteString("server=" + forwarder + "\n")
		}
		for _, domain := range cfg.Services.DNSServer.LocalDomains {
			b.WriteString("local=/" + domain + "/\n")
		}
	}
	if cfg.Services.DHCPServer.Enabled {
		for _, iface := range cfg.Interfaces {
			if iface.DHCPServer == nil {
				continue
			}
			b.WriteString("interface=" + iface.Name + "\n")
			b.WriteString(fmt.Sprintf("dhcp-range=%s,%s,%s\n", iface.DHCPServer.RangeStart, iface.DHCPServer.RangeEnd, iface.DHCPServer.LeaseTime))
			for _, dns := range iface.DHCPServer.DNS {
				b.WriteString("dhcp-option=option:dns-server," + dns + "\n")
			}
			if iface.DHCPServer.Domain != "" {
				b.WriteString("domain=" + iface.DHCPServer.Domain + "\n")
			}
		}
	}
	return b.String()
}

func renderChronyConfig(server config.NTPServiceConfig, client config.NTPClientConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by LAS.\n")
	for _, upstream := range client.Servers {
		b.WriteString("pool " + upstream + " iburst\n")
	}
	if server.Enabled {
		for _, iface := range server.Listen {
			b.WriteString("# serve NTP on " + iface + "\n")
		}
		b.WriteString("local stratum 10\n")
	}
	return b.String()
}

func renderKeepalived(entries []config.VRRP) string {
	var b strings.Builder
	b.WriteString("# Managed by LAS.\n")
	for _, entry := range entries {
		state := "BACKUP"
		if entry.Priority >= 150 {
			state = "MASTER"
		}
		b.WriteString(fmt.Sprintf("vrrp_instance %s {\n", entry.ID))
		b.WriteString("  state " + state + "\n")
		b.WriteString("  interface " + entry.Interface + "\n")
		b.WriteString(fmt.Sprintf("  virtual_router_id %d\n", entry.VRID))
		b.WriteString(fmt.Sprintf("  priority %d\n", entry.Priority))
		b.WriteString("  advert_int 1\n")
		if !entry.Preempt {
			b.WriteString("  nopreempt\n")
		}
		b.WriteString("  virtual_ipaddress {\n")
		for _, vip := range entry.VIPs {
			b.WriteString("    " + vip + "\n")
		}
		b.WriteString("  }\n}\n")
	}
	return b.String()
}

func renderFRRConfig(routing config.DynamicRouting, mpls config.MPLSConfig) string {
	var b strings.Builder
	b.WriteString("frr version 8\nfrr defaults traditional\nhostname las-router\nservice integrated-vtysh-config\n!\n")
	for _, routeMap := range routing.RouteMaps {
		action := routeMap.Action
		if action == "" {
			action = "permit"
		}
		b.WriteString(fmt.Sprintf("route-map %s %s %d\n", routeMap.Name, action, routeMap.Sequence))
		for _, match := range routeMap.Matches {
			b.WriteString(" match " + match + "\n")
		}
		for _, set := range routeMap.Sets {
			b.WriteString(" set " + set + "\n")
		}
		b.WriteString("!\n")
	}
	if routing.BGP.Enabled {
		b.WriteString(fmt.Sprintf("router bgp %d\n", routing.BGP.ASN))
		if routing.BGP.RouterID != "" {
			b.WriteString(" bgp router-id " + routing.BGP.RouterID + "\n")
		}
		for _, network := range routing.BGP.Networks {
			b.WriteString(" network " + network + "\n")
		}
		for _, peer := range routing.BGP.Peers {
			b.WriteString(fmt.Sprintf(" neighbor %s remote-as %d\n", peer.Address, peer.RemoteASN))
			if peer.Password != "" {
				b.WriteString(" neighbor " + peer.Address + " password " + peer.Password + "\n")
			}
			if peer.Multihop > 0 {
				b.WriteString(fmt.Sprintf(" neighbor %s ebgp-multihop %d\n", peer.Address, peer.Multihop))
			}
			if peer.RouteMapIn != "" {
				b.WriteString(" neighbor " + peer.Address + " route-map " + peer.RouteMapIn + " in\n")
			}
			if peer.RouteMapOut != "" {
				b.WriteString(" neighbor " + peer.Address + " route-map " + peer.RouteMapOut + " out\n")
			}
		}
		b.WriteString("!\n")
	}
	if routing.OSPF.Enabled {
		b.WriteString("router ospf\n")
		if routing.OSPF.RouterID != "" {
			b.WriteString(" ospf router-id " + routing.OSPF.RouterID + "\n")
		}
		for _, network := range routing.OSPF.Networks {
			b.WriteString(" network " + network + " area 0\n")
		}
		b.WriteString("!\n")
	}
	if routing.RIP.Enabled {
		b.WriteString("router rip\n")
		for _, network := range routing.RIP.Networks {
			b.WriteString(" network " + network + "\n")
		}
		b.WriteString("!\n")
	}
	if routing.BFD.Enabled {
		b.WriteString("bfd\n")
		for _, peer := range routing.BFD.Peers {
			b.WriteString(" peer " + peer.Address)
			if peer.Interface != "" {
				b.WriteString(" interface " + peer.Interface)
			}
			b.WriteString("\n")
		}
		b.WriteString("!\n")
	}
	if mpls.Enabled && mpls.LDP {
		b.WriteString("mpls ldp\n")
		for _, iface := range mpls.Interfaces {
			b.WriteString(" interface " + iface + "\n")
		}
		b.WriteString("!\n")
	}
	b.WriteString("line vty\n")
	return b.String()
}

func renderFRRDaemons(routing config.DynamicRouting, mpls config.MPLSConfig) string {
	yesNo := func(enabled bool) string {
		if enabled {
			return "yes"
		}
		return "no"
	}
	return fmt.Sprintf("zebra=yes\nbgpd=%s\nospfd=%s\nripd=%s\nbfdd=%s\nldpd=%s\nvtysh_enable=yes\n", yesNo(routing.BGP.Enabled), yesNo(routing.OSPF.Enabled), yesNo(routing.RIP.Enabled), yesNo(routing.BFD.Enabled), yesNo(mpls.Enabled && mpls.LDP))
}

func renderSNMPConfig(snmp config.SNMPConfig) string {
	community := snmp.Community
	if community == "" {
		community = "public"
	}
	listen := snmp.Listen
	if listen == "" {
		listen = "udp:161"
	}
	var b strings.Builder
	b.WriteString("# Managed by LAS.\n")
	b.WriteString("agentAddress " + listen + "\n")
	b.WriteString("rocommunity " + community + "\n")
	if snmp.Location != "" {
		b.WriteString("sysLocation " + snmp.Location + "\n")
	}
	if snmp.Contact != "" {
		b.WriteString("sysContact " + snmp.Contact + "\n")
	}
	return b.String()
}

func renderSoftflowdConfig(netflow config.NetFlowConfig) string {
	engine := netflow.Engine
	if engine == "" {
		engine = "softflowd"
	}
	collector := netflow.Collector
	if collector == "" {
		collector = "127.0.0.1"
	}
	port := netflow.Port
	if port == 0 {
		port = 2055
	}
	ifaces := strings.Join(netflow.Interfaces, ",")
	return fmt.Sprintf("# Managed by LAS.\nINTERFACE=\"%s\"\nOPTIONS=\"-n %s:%d\"\nENGINE=\"%s\"\n", ifaces, collector, port, engine)
}

func renderAccessConfig(access config.AccessConfig) string {
	var b strings.Builder
	b.WriteString("{\n")
	b.WriteString(fmt.Sprintf("  \"authEnabled\": %t,\n", access.AuthEnabled))
	b.WriteString(fmt.Sprintf("  \"sessionTtl\": %q,\n", access.SessionTTL))
	b.WriteString("  \"roles\": [\n")
	for i, role := range access.Roles {
		comma := ","
		if i == len(access.Roles)-1 {
			comma = ""
		}
		b.WriteString(fmt.Sprintf("    {\"name\": %q, \"permissions\": %q}%s\n", role.Name, strings.Join(role.Permissions, ","), comma))
	}
	b.WriteString("  ],\n  \"users\": [\n")
	for i, user := range access.Users {
		comma := ","
		if i == len(access.Users)-1 {
			comma = ""
		}
		b.WriteString(fmt.Sprintf("    {\"username\": %q, \"roles\": %q, \"disabled\": %t}%s\n", user.Username, strings.Join(user.Roles, ","), user.Disabled, comma))
	}
	b.WriteString("  ]\n}\n")
	return b.String()
}

func renderRollbackWatchdog(watchdog config.RollbackWatchdog) string {
	target := watchdog.ProbeTarget
	if target == "" {
		target = "1.1.1.1"
	}
	recovery := watchdog.RecoveryPath
	if recovery == "" {
		recovery = "/root/ruleset.before"
	}
	return fmt.Sprintf("#!/usr/bin/env bash\nset -euo pipefail\nif ! ping -c 3 -W 2 %s >/dev/null 2>&1; then\n  if [[ -f %s ]]; then nft -f %s; fi\nfi\n", shellQuote(target), shellQuote(recovery), shellQuote(recovery))
}

func renderBackupScript(backup config.BackupConfig) string {
	dest := backup.Destination
	if dest == "" {
		dest = "/var/backups/las"
	}
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\nset -euo pipefail\n")
	b.WriteString("dest=" + shellQuote(dest) + "\n")
	b.WriteString("install -d -m 0700 \"$dest\"\n")
	b.WriteString("tar -czf \"$dest/las-$(date +%Y%m%d-%H%M%S).tar.gz\" /etc/las /usr/share/las 2>/dev/null\n")
	if backup.Encrypt {
		b.WriteString("# Encryption hook: configure age/gpg recipient before enabling encrypted backups.\n")
	}
	return b.String()
}

func filepathDir(path string) string {
	idx := strings.LastIndex(path, "/")
	if idx <= 0 {
		return "."
	}
	return path[:idx]
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

func resolveRuleRouteWithGroups(rule config.RouteRule, tunnels []config.Tunnel, groups []config.WANGroup) (int, int) {
	mark, table := resolveRuleRoute(rule, tunnels)
	if rule.Action.Type == "wan-group" || rule.Action.Type == "load-balance" {
		for _, group := range groups {
			if group.ID == rule.Action.Target {
				if mark == 0 {
					mark = group.Mark
				}
				if table == 0 {
					table = group.Table
				}
				break
			}
		}
	}
	return mark, table
}

func addWANGroupPlan(plan *control.Plan, group config.WANGroup) {
	if group.Table == 0 {
		plan.AddWarning("WAN group %s is enabled without table; it can be edited but cannot install a routing table", group.ID)
		return
	}

	if group.Mode == "weighted-ecmp" {
		args := []string{"route", "replace", "default", "table", strconv.Itoa(group.Table)}
		for _, member := range group.Members {
			args = append(args, "nexthop")
			if member.Gateway != "" {
				args = append(args, "via", member.Gateway)
			}
			args = append(args, "dev", member.Interface)
			if member.Weight > 0 {
				args = append(args, "weight", strconv.Itoa(member.Weight))
			}
		}
		plan.AddCommand("install weighted WAN group "+group.ID, "ip", args...)
		return
	}

	for _, member := range group.Members {
		metric := member.Priority
		if metric == 0 {
			metric = 100
		}
		args := []string{"route", "replace", "default", "table", strconv.Itoa(group.Table), "dev", member.Interface, "metric", strconv.Itoa(metric)}
		if member.Gateway != "" {
			args = append([]string{"route", "replace", "default", "table", strconv.Itoa(group.Table), "via", member.Gateway}, "dev", member.Interface, "metric", strconv.Itoa(metric))
		}
		plan.AddCommand("install failover WAN member "+group.ID+"/"+member.Interface, "ip", args...)
	}
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
	b.WriteString("# Managed by lasd. Use this profile from an ICAP/proxy integration.\n")
	b.WriteString(fmt.Sprintf("mode=%s\n", av.Mode))
	b.WriteString(fmt.Sprintf("max_file_size_mb=%d\n", av.MaxFileSizeMB))
	b.WriteString(fmt.Sprintf("quarantine_dir=%s\n", av.QuarantineDir))
	b.WriteString("interfaces=" + strings.Join(av.Interfaces, ",") + "\n")
	return b.String()
}

func renderDNSMasqConfig(dns config.DNSFilteringConf) string {
	var b strings.Builder
	b.WriteString("# Managed by lasd.\n")
	b.WriteString("domain-needed\nbogus-priv\n")
	for _, upstream := range dns.Upstream {
		b.WriteString("server=" + upstream + "\n")
	}
	for _, blocklist := range dns.Blocklists {
		b.WriteString("# blocklist=" + blocklist + "\n")
	}
	return b.String()
}

func renderCaptivePortalConfig(portal config.CaptivePortal) string {
	var b strings.Builder
	b.WriteString("# Managed by LAS.\n")
	b.WriteString("engine=" + captivePortalService(portal.Engine) + "\n")
	b.WriteString("interfaces=" + strings.Join(portal.Interfaces, ",") + "\n")
	b.WriteString("login_url=" + portal.LoginURL + "\n")
	b.WriteString(fmt.Sprintf("radius=%t\n", portal.RADIUS))
	return b.String()
}

func captivePortalService(engine string) string {
	if engine == "" || engine == "opennds" {
		return "opennds"
	}
	return engine
}

func renderRADIUSConfig(radius config.RADIUSConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by LAS.\n")
	b.WriteString("servers=" + strings.Join(radius.Servers, ",") + "\n")
	b.WriteString("secret=" + radius.Secret + "\n")
	b.WriteString("nas_id=" + radius.NASID + "\n")
	return b.String()
}

func renderUPnPConfig(upnp config.UPnPConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by LAS.\n")
	if upnp.ExternalIface != "" {
		b.WriteString("ext_ifname=" + upnp.ExternalIface + "\n")
	}
	for _, iface := range upnp.InternalIfaces {
		b.WriteString("listening_ip=" + iface + "\n")
	}
	b.WriteString("secure_mode=yes\n")
	b.WriteString("enable_natpmp=yes\n")
	b.WriteString("enable_upnp=yes\n")
	return b.String()
}
