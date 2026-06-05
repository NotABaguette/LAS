package control

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type HostStatus struct {
	Platform string            `json:"platform"`
	Commands map[string]string `json:"commands"`
	Services map[string]string `json:"services"`
	Time     time.Time         `json:"time"`
}

func ProbeStatus(ctx context.Context) HostStatus {
	status := HostStatus{
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
		Commands: map[string]string{
			"ip":       commandVersion(ctx, "ip", "-V"),
			"nft":      commandVersion(ctx, "nft", "--version"),
			"wg":       commandVersion(ctx, "wg", "--version"),
			"xray":     commandVersion(ctx, "xray", "version"),
			"sing-box": commandVersion(ctx, "sing-box", "version"),
			"curl":     commandVersion(ctx, "curl", "--version"),
			"dig":      commandVersion(ctx, "dig", "-v"),
			"traceroute": commandVersion(ctx, "traceroute",
				"--version"),
			"chrony":   commandVersion(ctx, "chronyd", "-v"),
			"frr":      commandVersion(ctx, "vtysh", "-v"),
			"suricata": commandVersion(ctx, "suricata", "--build-info"),
			"clamd":    commandVersion(ctx, "clamd", "--version"),
		},
		Services: map[string]string{},
		Time:     time.Now().UTC(),
	}

	if runtime.GOOS == "linux" {
		for _, service := range []string{"lasd", "las-updater.timer", "nftables", "dnsmasq", "chrony", "frr", "suricata", "clamav-daemon", "strongswan", "xl2tpd", "openvpn", "xray", "sing-box"} {
			status.Services[service] = commandVersion(ctx, "systemctl", "is-active", service)
		}
	}
	return status
}

func commandVersion(ctx context.Context, program string, args ...string) string {
	cmd := exec.CommandContext(ctx, program, args...)
	output, err := cmd.CombinedOutput()
	value := strings.TrimSpace(string(output))
	if err != nil {
		if value == "" {
			return "missing"
		}
		return value
	}
	if idx := strings.IndexByte(value, '\n'); idx >= 0 {
		value = value[:idx]
	}
	if value == "" {
		return "available"
	}
	return value
}
