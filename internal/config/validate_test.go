package config

import "testing"

func TestDefaultConfigValidates(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should validate: %v", err)
	}
}

func TestInvalidRuleTargetFails(t *testing.T) {
	cfg := Default()
	cfg.Routing.Rules = []RouteRule{
		{
			ID:       "bad-target",
			Name:     "bad target",
			Enabled:  true,
			Priority: 100,
			Action: RuleAction{
				Type:   "tunnel",
				Target: "missing",
			},
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for missing tunnel")
	}
}
