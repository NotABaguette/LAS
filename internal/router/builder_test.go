package router

import (
	"strings"
	"testing"

	"debian-router/internal/config"
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
