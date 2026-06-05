package router

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"debian-router/internal/config"
)

func BuildNftables(cfg config.Config) (string, []string) {
	var b strings.Builder
	var warnings []string

	b.WriteString("# Managed by debian-routerd. Manual edits will be overwritten.\n")
	b.WriteString("table inet debian_router {\n")
	writeInputChain(&b, cfg)
	writePreroutingChain(&b, cfg, &warnings)
	writeForwardChain(&b, cfg, &warnings)
	writePostroutingChain(&b, cfg)
	b.WriteString("}\n")

	return b.String(), warnings
}

func writeInputChain(b *strings.Builder, cfg config.Config) {
	policy := "accept"
	if cfg.Security.Firewall {
		policy = "drop"
	}
	fmt.Fprintf(b, "  chain input {\n    type filter hook input priority filter; policy %s;\n", policy)
	b.WriteString("    iifname \"lo\" accept\n")
	if cfg.Security.AllowEstablished {
		b.WriteString("    ct state established,related accept\n")
	}
	b.WriteString("    ct state invalid drop\n")
	for _, cidr := range cfg.Host.ManagementCIDRs {
		family := nftFamily(cidr)
		for _, port := range cfg.Security.ManagementPorts {
			fmt.Fprintf(b, "    %s saddr %s tcp dport %d accept comment \"management\"\n", family, cidr, port)
		}
	}
	b.WriteString("    ip protocol icmp accept\n")
	b.WriteString("    ip6 nexthdr icmpv6 accept\n")
	b.WriteString("  }\n")
}

func writePreroutingChain(b *strings.Builder, cfg config.Config, warnings *[]string) {
	b.WriteString("  chain prerouting {\n    type filter hook prerouting priority mangle; policy accept;\n")

	rules := append([]config.RouteRule{}, cfg.Routing.Rules...)
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if isFilterAction(rule.Action.Type) {
			continue
		}
		for _, domain := range rule.Match.Domains {
			*warnings = append(*warnings, fmt.Sprintf("rule %s has domain match %q; feed resolved IPs into nft sets or DNS filtering before enforcing", rule.ID, domain))
		}
		for _, geo := range rule.Match.GeoIP {
			*warnings = append(*warnings, fmt.Sprintf("rule %s has GeoIP match %q; generate country IP sets before enforcing", rule.ID, geo))
		}

		expressions := nftMatchExpressions(rule, warnings)
		action := nftAction(rule, cfg.Tunnels)
		if action == "" {
			continue
		}
		if len(expressions) == 0 {
			fmt.Fprintf(b, "    %s comment %q\n", action, rule.ID)
			continue
		}
		for _, expr := range expressions {
			fmt.Fprintf(b, "    %s %s comment %q\n", expr, action, rule.ID)
		}
	}

	if cfg.Security.IPS.Enabled && cfg.Security.IPS.Mode == "nfqueue" {
		queue := cfg.Security.IPS.NFQueue
		fmt.Fprintf(b, "    queue num %d bypass comment \"suricata nfqueue\"\n", queue)
	}
	b.WriteString("  }\n")
}

func writeForwardChain(b *strings.Builder, cfg config.Config, warnings *[]string) {
	b.WriteString("  chain forward {\n    type filter hook forward priority filter; policy accept;\n")
	if cfg.Security.AllowEstablished {
		b.WriteString("    ct state established,related accept\n")
	}
	b.WriteString("    ct state invalid drop\n")

	rules := append([]config.RouteRule{}, cfg.Routing.Rules...)
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})
	for _, rule := range rules {
		if !rule.Enabled || !isFilterAction(rule.Action.Type) {
			continue
		}
		for _, domain := range rule.Match.Domains {
			*warnings = append(*warnings, fmt.Sprintf("rule %s has domain match %q; feed resolved IPs into nft sets or DNS filtering before enforcing", rule.ID, domain))
		}
		for _, geo := range rule.Match.GeoIP {
			*warnings = append(*warnings, fmt.Sprintf("rule %s has GeoIP match %q; generate country IP sets before enforcing", rule.ID, geo))
		}
		expressions := nftMatchExpressions(rule, warnings)
		action := nftAction(rule, cfg.Tunnels)
		if action == "" {
			continue
		}
		if len(expressions) == 0 {
			fmt.Fprintf(b, "    %s comment %q\n", action, rule.ID)
			continue
		}
		for _, expr := range expressions {
			fmt.Fprintf(b, "    %s %s comment %q\n", expr, action, rule.ID)
		}
	}

	b.WriteString("  }\n")
}

func writePostroutingChain(b *strings.Builder, cfg config.Config) {
	if !cfg.Security.NAT {
		return
	}
	b.WriteString("  chain postrouting {\n    type nat hook postrouting priority srcnat; policy accept;\n")
	for _, iface := range cfg.Interfaces {
		if iface.Enabled && (iface.Masquerade || iface.Role == "wan") {
			fmt.Fprintf(b, "    oifname %q masquerade comment %q\n", iface.Name, "nat "+iface.Name)
		}
	}
	for _, rule := range cfg.Routing.Rules {
		if rule.Enabled && rule.Action.NAT && rule.Action.Target != "" {
			fmt.Fprintf(b, "    oifname %q masquerade comment %q\n", rule.Action.Target, "rule nat "+rule.ID)
		}
	}
	b.WriteString("  }\n")
}

func nftMatchExpressions(rule config.RouteRule, warnings *[]string) []string {
	base := []string{}
	if rule.Match.InputIface != "" {
		base = append(base, fmt.Sprintf("iifname %q", rule.Match.InputIface))
	}
	if rule.Match.OutputIface != "" {
		base = append(base, fmt.Sprintf("oifname %q", rule.Match.OutputIface))
	}
	if len(rule.Match.Protocols) > 0 {
		base = append(base, "meta l4proto "+nftSet(rule.Match.Protocols))
	}

	portExprs := nftPortExpressions(rule, warnings)
	if len(portExprs) == 0 {
		portExprs = []string{""}
	}

	src4, src6 := splitCIDRs(rule.Match.SourceCIDRs)
	dst4, dst6 := splitCIDRs(rule.Match.DestinationCIDRs)
	cidrCombos := combineCIDRs(src4, src6, dst4, dst6)
	if len(cidrCombos) == 0 {
		cidrCombos = []string{""}
	}

	var out []string
	for _, cidrExpr := range cidrCombos {
		for _, portExpr := range portExprs {
			parts := append([]string{}, base...)
			if cidrExpr != "" {
				parts = append(parts, cidrExpr)
			}
			if portExpr != "" {
				parts = append(parts, portExpr)
			}
			out = append(out, strings.Join(parts, " "))
		}
	}
	return out
}

func nftPortExpressions(rule config.RouteRule, warnings *[]string) []string {
	var out []string
	protos := rule.Match.Protocols
	if len(protos) == 0 {
		protos = []string{"tcp", "udp"}
	}
	for _, proto := range protos {
		if proto != "tcp" && proto != "udp" {
			if len(rule.Match.SourcePorts) > 0 || len(rule.Match.DestinationPorts) > 0 {
				*warnings = append(*warnings, fmt.Sprintf("rule %s has ports with non-TCP/UDP protocol %s; skipping port expression for that protocol", rule.ID, proto))
			}
			continue
		}
		parts := []string{}
		if len(rule.Match.SourcePorts) > 0 {
			parts = append(parts, fmt.Sprintf("%s sport %s", proto, nftPortSet(rule.Match.SourcePorts)))
		}
		if len(rule.Match.DestinationPorts) > 0 {
			parts = append(parts, fmt.Sprintf("%s dport %s", proto, nftPortSet(rule.Match.DestinationPorts)))
		}
		if len(parts) > 0 {
			out = append(out, strings.Join(parts, " "))
		}
	}
	return out
}

func combineCIDRs(src4, src6, dst4, dst6 []string) []string {
	var out []string
	if len(src4) > 0 || len(dst4) > 0 {
		parts := []string{}
		if len(src4) > 0 {
			parts = append(parts, "ip saddr "+nftSet(src4))
		}
		if len(dst4) > 0 {
			parts = append(parts, "ip daddr "+nftSet(dst4))
		}
		out = append(out, strings.Join(parts, " "))
	}
	if len(src6) > 0 || len(dst6) > 0 {
		parts := []string{}
		if len(src6) > 0 {
			parts = append(parts, "ip6 saddr "+nftSet(src6))
		}
		if len(dst6) > 0 {
			parts = append(parts, "ip6 daddr "+nftSet(dst6))
		}
		out = append(out, strings.Join(parts, " "))
	}
	return out
}

func nftAction(rule config.RouteRule, tunnels []config.Tunnel) string {
	switch rule.Action.Type {
	case "blackhole":
		if rule.Action.Log {
			return fmt.Sprintf("log prefix %q drop", "debian-router "+rule.ID+" ")
		}
		return "drop"
	case "reject":
		if rule.Action.Log {
			return fmt.Sprintf("log prefix %q reject", "debian-router "+rule.ID+" ")
		}
		return "reject"
	case "direct":
		return "meta mark set 0 accept"
	case "interface", "tunnel", "scan", "mirror":
		mark := rule.Action.Mark
		if mark == 0 && rule.Action.Type == "tunnel" {
			for _, tunnel := range tunnels {
				if tunnel.ID == rule.Action.Target {
					mark = tunnel.Mark
					break
				}
			}
		}
		if mark == 0 {
			return ""
		}
		if rule.Action.Log {
			return fmt.Sprintf("log prefix %q meta mark set 0x%x accept", "debian-router "+rule.ID+" ", mark)
		}
		return fmt.Sprintf("meta mark set 0x%x accept", mark)
	default:
		return ""
	}
}

func isFilterAction(actionType string) bool {
	return actionType == "blackhole" || actionType == "reject"
}

func splitCIDRs(values []string) ([]string, []string) {
	var v4 []string
	var v6 []string
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			continue
		}
		if prefix.Addr().Is4() {
			v4 = append(v4, value)
		} else {
			v6 = append(v6, value)
		}
	}
	return v4, v6
}

func nftFamily(cidr string) string {
	prefix, err := netip.ParsePrefix(cidr)
	if err == nil && prefix.Addr().Is6() {
		return "ip6"
	}
	return "ip"
}

func nftSet(values []string) string {
	if len(values) == 1 {
		return values[0]
	}
	return "{ " + strings.Join(values, ", ") + " }"
}

func nftPortSet(values []config.PortRange) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		if value.From == value.To {
			parts = append(parts, strconv.Itoa(value.From))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", value.From, value.To))
		}
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}
