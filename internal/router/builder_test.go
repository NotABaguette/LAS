package router

import (
	"fmt"
	"strings"
	"testing"

	"github.com/NotABaguette/LAS/internal/config"
)

func TestBuildPlanDefault(t *testing.T) {
	cfg := config.Default()
	plan, err := BuildPlan(cfg)
	if err != nil {
		t.Fatalf("BuildPlan failed: %v", err)
	}
	if len(plan.Steps) == 0 {
		t.Fatal("expected plan steps")
	}
}

func TestBuildNftablesIncludesMark(t *testing.T) {
	cfg := config.Default()
	cfg.Tunnels = []config.Tunnel{
		{
			ID:            "wg",
			Type:          "wireguard",
			Enabled:       true,
			InterfaceName: "wg0",
			Mark:          4097,
			Table:         101,
		},
	}
	cfg.Routing.Rules = []config.RouteRule{
		{
			ID:       "marked",
			Enabled:  true,
			Priority: 100,
			Match: config.RuleMatch{
				InputIface:       "enp2s0",
				SourceCIDRs:      []string{"192.168.88.0/24"},
				DestinationCIDRs: []string{"10.20.0.0/16"},
				Protocols:        []string{"tcp"},
			},
			Action: config.RuleAction{
				Type:   "tunnel",
				Target: "wg",
			},
		},
	}
	nft, _ := BuildNftables(cfg)
	if !strings.Contains(nft, "meta mark set 0x1001") {
		t.Fatalf("expected fwmark in nftables config:\n%s", nft)
	}
}

func TestBuildNftablesIncludesRouteSetWANGroupAndPortForward(t *testing.T) {
	cfg := config.Default()
	cfg.Routing.Sets = []config.RouteSet{
		{
			ID:      "geo-ir",
			Type:    "country",
			Enabled: true,
			CIDRs:   []string{"5.52.0.0/14"},
		},
	}
	cfg.Routing.WANGroups = []config.WANGroup{
		{
			ID:      "sdwan",
			Enabled: true,
			Mode:    "weighted-ecmp",
			Mark:    8193,
			Table:   201,
			Members: []config.WANMember{{Interface: "enp1s0", Weight: 1}},
		},
	}
	cfg.Routing.Rules = []config.RouteRule{
		{
			ID:       "geo",
			Enabled:  true,
			Priority: 100,
			Match: config.RuleMatch{
				InputIface: "enp2s0",
				Sets:       []string{"geo-ir"},
			},
			Action: config.RuleAction{
				Type:   "wan-group",
				Target: "sdwan",
			},
		},
	}
	cfg.Security.PortForwards = []config.PortForward{
		{
			ID:           "https",
			Enabled:      true,
			InputIface:   "enp1s0",
			Protocols:    []string{"tcp"},
			ExternalPort: 443,
			InternalIP:   "192.168.88.10",
			InternalPort: 8443,
		},
	}

	nft, _ := BuildNftables(cfg)
	for _, expected := range []string{
		"set geo_ir_v4",
		"ip daddr @geo_ir_v4",
		"meta mark set 0x2001",
		"tcp dport 443 dnat to 192.168.88.10:8443",
	} {
		if !strings.Contains(nft, expected) {
			t.Fatalf("expected %q in nftables config:\n%s", expected, nft)
		}
	}
}

func TestBuildPlanRendersSSLVPNTunnels(t *testing.T) {
	cfg := config.Default()
	cfg.Tunnels = []config.Tunnel{
		{
			ID:             "ovpn",
			Type:           "openvpn",
			Direction:      "client",
			Enabled:        true,
			InterfaceName:  "tun-ovpn0",
			RemoteEndpoint: "vpn.example.com:1194",
			Credentials: map[string]string{
				"caFile":   "/etc/las/certs/ca.crt",
				"authFile": "/etc/las/openvpn/ovpn.auth",
			},
			Options: map[string]string{"proto": "udp"},
		},
		{
			ID:             "oc",
			Type:           "openconnect",
			Direction:      "client",
			Enabled:        true,
			InterfaceName:  "tun-oc0",
			RemoteEndpoint: "https://vpn.example.com",
			Credentials: map[string]string{
				"username":     "user",
				"passwordFile": "/etc/las/openconnect/oc.pass",
			},
			Options: map[string]string{"protocol": "anyconnect"},
		},
		{
			ID:             "fgt",
			Type:           "fortigate-ssl",
			Direction:      "client",
			Enabled:        true,
			InterfaceName:  "ppp-fgt0",
			RemoteEndpoint: "fortigate.example.com:443",
			Credentials: map[string]string{
				"username":     "user",
				"passwordFile": "/etc/las/openfortivpn/fgt.pass",
			},
		},
	}

	plan, err := BuildPlan(cfg)
	if err != nil {
		t.Fatalf("BuildPlan failed: %v", err)
	}
	joined := planText(plan)
	for _, expected := range []string{
		"/etc/openvpn/client/ovpn.conf",
		"openvpn-client@ovpn",
		"las-openconnect-oc.service",
		"/usr/sbin/openconnect",
		"las-openfortivpn-fgt.service",
		"/usr/bin/openfortivpn",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected %q in plan:\n%s", expected, joined)
		}
	}
}

func TestBuildPlanRendersDNSNTPAndACME(t *testing.T) {
	cfg := config.Default()
	cfg.Services.DHCPServer.Enabled = true
	cfg.Interfaces[1].DHCPServer = &config.DHCPServer{
		RangeStart: "192.168.88.50",
		RangeEnd:   "192.168.88.250",
		LeaseTime:  "12h",
		DNS:        []string{"192.168.88.1"},
		Domain:     "lan",
	}
	cfg.Services.DNSServer.Enabled = true
	cfg.Services.DNSServer.AddressOverrides = []config.DNSOverride{{Domain: "blocked.example", Address: "0.0.0.0"}}
	cfg.Services.NTPServer.Enabled = true
	cfg.Services.NTPServer.AllowCIDRs = []string{"192.168.88.0/24"}
	cfg.Services.CertificateStore.LetsEncrypt.Enabled = true
	cfg.Services.CertificateStore.LetsEncrypt.Email = "admin@example.com"
	cfg.Services.CertificateStore.LetsEncrypt.Certificates = []config.ACMECertificate{
		{ID: "router.example.com", Domains: []string{"router.example.com"}, Method: "webroot"},
	}

	plan, err := BuildPlan(cfg)
	if err != nil {
		t.Fatalf("BuildPlan failed: %v", err)
	}
	joined := planText(plan)
	for _, expected := range []string{
		"/etc/dnsmasq.d/las-services.conf",
		"address=/blocked.example/0.0.0.0",
		"/etc/systemd/resolved.conf.d/las.conf",
		"/etc/chrony/conf.d/las.conf",
		"allow 192.168.88.0/24",
		"certbot",
		"router.example.com",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected %q in plan:\n%s", expected, joined)
		}
	}
}

func planText(plan interface{}) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(fmt.Sprint(plan)), "\\n", "\n"), "\\t", "\t")
}
