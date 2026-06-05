package router

import (
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
