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
	addCertificateStorePlan(&plan, cfg.Services.CertificateStore)
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
	}
}

func addCertificateStorePlan(plan *control.Plan, store config.CertificateStore) {
	if !store.Enabled && !store.LetsEncrypt.Enabled {
		return
	}
	dir := store.Directory
	if dir == "" {
		dir = "/etc/las/certs"
	}
	trustStore := store.TrustStore
	if trustStore == "" {
		trustStore = "/usr/local/share/ca-certificates"
	}
	plan.AddCommand("ensure LAS certificate store", "install", "-d", "-m", "0750", dir)
	if len(store.Authorities) > 0 {
		plan.AddCommand("ensure system trust store", "install", "-d", "-m", "0755", trustStore)
	}
	installedCA := false
	for _, authority := range store.Authorities {
		target := dir + "/authorities/" + authority.ID + ".crt"
		if authority.Install {
			target = trustStore + "/las-" + authority.ID + ".crt"
			installedCA = true
		}
		plan.AddCommand("ensure CA directory "+authority.ID, "install", "-d", "-m", "0750", filepathDir(target))
		if authority.PEM != "" {
			plan.AddWrite("render trusted CA "+authority.ID, target, "0644", authority.PEM)
		} else {
			plan.AddCommand("install trusted CA "+authority.ID, "install", "-m", "0644", authority.SourceFile, target)
		}
	}
	if installedCA {
		plan.AddCommand("refresh Debian CA certificates", "update-ca-certificates")
	}
	for _, cert := range store.Certificates {
		plan.AddWrite("render managed certificate metadata "+cert.ID, dir+"/"+cert.ID+".json", "0600", renderManagedCertificateMetadata(cert))
		if cert.CertFile == "" || cert.KeyFile == "" {
			plan.AddWarning("managed certificate %s is missing certFile or keyFile", cert.ID)
		}
	}
	if store.LetsEncrypt.Enabled {
		acme := store.LetsEncrypt
		webroot := acme.Webroot
		if webroot == "" {
			webroot = "/var/www/letsencrypt"
		}
		plan.AddCommand("ensure Let's Encrypt webroot", "install", "-d", "-m", "0755", webroot)
		plan.AddCommand("ensure certbot deploy hook directory", "install", "-d", "-m", "0755", "/etc/letsencrypt/renewal-hooks/deploy")
		plan.AddWrite("render LAS certbot deploy hook", "/etc/letsencrypt/renewal-hooks/deploy/las.sh", "0755", renderCertbotDeployHook(store))
		for _, cert := range acme.Certificates {
			args := []string{"certonly", "--non-interactive", "--agree-tos", "--email", acme.Email, "--cert-name", cert.ID}
			for _, domain := range cert.Domains {
				args = append(args, "-d", domain)
			}
			method := cert.Method
			if method == "" {
				method = "webroot"
			}
			switch method {
			case "webroot":
				certWebroot := cert.Webroot
				if certWebroot == "" {
					certWebroot = webroot
				}
				args = append(args, "--webroot", "-w", certWebroot)
			case "standalone":
				args = append(args, "--standalone")
			case "dns":
				args = append(args, "--preferred-challenges", "dns")
				if cert.DNSProvider != "" {
					args = append(args, "--authenticator", "dns-"+cert.DNSProvider)
				}
				plan.AddWarning("Let's Encrypt certificate %s uses DNS challenge; install and configure the matching certbot DNS plugin/credentials", cert.ID)
			}
			if acme.DirectoryURL != "" {
				args = append(args, "--server", acme.DirectoryURL)
			}
			if acme.Staging || cert.Staging {
				args = append(args, "--staging")
			}
			if cert.KeyType != "" {
				args = append(args, "--key-type", cert.KeyType)
			}
			if cert.DeployHook != "" {
				args = append(args, "--deploy-hook", cert.DeployHook)
			}
			plan.AddCommand("request/renew Let's Encrypt certificate "+cert.ID, "certbot", args...)
		}
		if acme.RenewTimer {
			plan.AddCommand("enable certbot auto-renewal", "systemctl", "enable", "--now", "certbot.timer")
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

		serviceManagedDevice := false
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
			addOpenVPNPlan(plan, tunnel)
			serviceManagedDevice = true
		case "openconnect", "anyconnect", "globalprotect", "pulse-secure":
			addOpenConnectPlan(plan, tunnel, openConnectProtocol(tunnel.Type, tunnel.Options))
			serviceManagedDevice = true
		case "fortigate-ssl", "fortinet-ssl":
			addFortiGateSSLPlan(plan, tunnel)
			serviceManagedDevice = true
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
			serviceManagedDevice = true
		case "vless", "vmess", "vless-xhttp", "xhttp", "xray", "sing-box":
			addProxyTunnelServicePlan(plan, tunnel)
			serviceManagedDevice = true
		case "tailscale", "zerotier":
			service := tunnel.Type
			if tunnel.Type == "zerotier" {
				service = "zerotier-one"
			}
			plan.AddWarning("%s tunnel %s is managed by its own control plane; lasd routes traffic into %s", tunnel.Type, tunnel.ID, tunnel.InterfaceName)
			plan.AddCommand("enable "+service+" service", "systemctl", "enable", "--now", service)
			serviceManagedDevice = true
		case "custom":
			service := tunnel.Options["service"]
			if service == "" {
				plan.AddWarning("custom tunnel %s has no options.service", tunnel.ID)
			} else {
				plan.AddCommand("enable custom tunnel service "+service, "systemctl", "enable", "--now", service)
				serviceManagedDevice = true
			}
		}

		if serviceManagedDevice {
			if tunnel.MTU > 0 || len(tunnel.LocalAddresses) > 0 {
				plan.AddWarning("tunnel %s is service-managed; MTU and local addresses are rendered into the backend config where supported", tunnel.ID)
			}
		} else if tunnel.MTU > 0 {
			plan.AddCommand("set mtu for "+tunnel.InterfaceName, "ip", "link", "set", "dev", tunnel.InterfaceName, "mtu", strconv.Itoa(tunnel.MTU))
		}
		if !serviceManagedDevice {
			plan.AddCommand("bring up tunnel "+tunnel.InterfaceName, "ip", "link", "set", "dev", tunnel.InterfaceName, "up")
			for _, address := range tunnel.LocalAddresses {
				plan.AddCommand("assign "+address+" to "+tunnel.InterfaceName, "ip", "address", "replace", address, "dev", tunnel.InterfaceName)
			}
		}
		if tunnel.Table > 0 {
			plan.AddCommand("route tunnel table "+strconv.Itoa(tunnel.Table), "ip", "route", "replace", "default", "dev", tunnel.InterfaceName, "table", strconv.Itoa(tunnel.Table))
		}
	}
}

func addOpenVPNPlan(plan *control.Plan, tunnel config.Tunnel) {
	profilePath := openVPNProfilePath(tunnel)
	plan.AddCommand("ensure OpenVPN profile directory", "install", "-d", "-m", "0750", filepathDir(profilePath))
	if source := tunnel.Credentials["configFile"]; source != "" && source != profilePath {
		plan.AddCommand("install OpenVPN profile "+tunnel.ID, "install", "-m", "0600", source, profilePath)
	} else {
		if authPath := generatedOpenVPNAuthPath(tunnel); authPath != "" {
			plan.AddCommand("ensure OpenVPN LAS secret directory", "install", "-d", "-m", "0750", filepathDir(authPath))
			plan.AddWrite("render OpenVPN auth file "+tunnel.ID, authPath, "0600", tunnel.Credentials["username"]+"\n"+tunnel.Credentials["password"]+"\n")
			plan.AddWarning("OpenVPN tunnel %s contains inline username/password; prefer credentials.authFile to avoid secrets in apply plans", tunnel.ID)
		}
		plan.AddWrite("render OpenVPN profile "+tunnel.ID, profilePath, "0600", renderOpenVPNConfig(tunnel))
	}
	service := "openvpn-client@" + tunnel.ID
	if tunnel.Direction == "server" {
		service = "openvpn-server@" + tunnel.ID
	}
	plan.AddCommand("enable OpenVPN tunnel "+tunnel.ID, "systemctl", "enable", "--now", service)
}

func addOpenConnectPlan(plan *control.Plan, tunnel config.Tunnel, protocol string) {
	envPath := "/etc/las/openconnect/" + tunnel.ID + ".env"
	serviceName := "las-openconnect-" + tunnel.ID + ".service"
	plan.AddCommand("ensure OpenConnect profile directory", "install", "-d", "-m", "0750", "/etc/las/openconnect")
	if tunnel.Credentials["username"] == "" {
		plan.AddWarning("OpenConnect tunnel %s has no credentials.username; non-interactive service auth may fail", tunnel.ID)
	}
	if tunnel.Credentials["passwordFile"] == "" && tunnel.Credentials["cookieFile"] == "" {
		plan.AddWarning("OpenConnect tunnel %s has no credentials.passwordFile or credentials.cookieFile; configure one for unattended startup", tunnel.ID)
	}
	plan.AddWrite("render OpenConnect environment "+tunnel.ID, envPath, "0600", renderOpenConnectEnv(tunnel, protocol))
	plan.AddWrite("render OpenConnect service "+tunnel.ID, "/etc/systemd/system/"+serviceName, "0644", renderOpenConnectService(envPath))
	plan.AddCommand("reload systemd for OpenConnect "+tunnel.ID, "systemctl", "daemon-reload")
	plan.AddCommand("enable OpenConnect tunnel "+tunnel.ID, "systemctl", "enable", "--now", serviceName)
}

func addFortiGateSSLPlan(plan *control.Plan, tunnel config.Tunnel) {
	confPath := "/etc/las/openfortivpn/" + tunnel.ID + ".conf"
	serviceName := "las-openfortivpn-" + tunnel.ID + ".service"
	plan.AddCommand("ensure FortiGate SSL VPN profile directory", "install", "-d", "-m", "0750", "/etc/las/openfortivpn")
	if tunnel.Credentials["username"] == "" {
		plan.AddWarning("FortiGate SSL VPN tunnel %s has no credentials.username; non-interactive service auth may fail", tunnel.ID)
	}
	if tunnel.Credentials["password"] == "" && tunnel.Credentials["passwordFile"] == "" {
		plan.AddWarning("FortiGate SSL VPN tunnel %s has no credentials.password or credentials.passwordFile; configure one for unattended startup", tunnel.ID)
	}
	if tunnel.Credentials["password"] != "" {
		plan.AddWarning("FortiGate SSL VPN tunnel %s contains inline password; prefer credentials.passwordFile when possible", tunnel.ID)
	}
	plan.AddWrite("render FortiGate SSL VPN profile "+tunnel.ID, confPath, "0600", renderFortiGateSSLConfig(tunnel))
	plan.AddWrite("render FortiGate SSL VPN service "+tunnel.ID, "/etc/systemd/system/"+serviceName, "0644", renderFortiGateSSLService(tunnel, confPath))
	plan.AddCommand("reload systemd for FortiGate SSL VPN "+tunnel.ID, "systemctl", "daemon-reload")
	plan.AddCommand("enable FortiGate SSL VPN tunnel "+tunnel.ID, "systemctl", "enable", "--now", serviceName)
}

func addProxyTunnelServicePlan(plan *control.Plan, tunnel config.Tunnel) {
	engine := tunnel.Options["engine"]
	if engine == "" {
		engine = defaultProxyEngine(tunnel.Type)
	}
	configFile := tunnel.Credentials["configFile"]
	if configFile == "" {
		plan.AddWarning("%s tunnel %s has no credentials.configFile", tunnel.Type, tunnel.ID)
		return
	}
	serviceName := "las-" + engine + "-" + tunnel.ID + ".service"
	plan.AddWrite("render "+engine+" tunnel service "+tunnel.ID, "/etc/systemd/system/"+serviceName, "0644", renderProxyTunnelService(engine, tunnel, configFile))
	plan.AddCommand("reload systemd for "+engine+" tunnel "+tunnel.ID, "systemctl", "daemon-reload")
	plan.AddCommand("enable "+engine+" tunnel "+tunnel.ID, "systemctl", "enable", "--now", serviceName)
}

func renderManagedCertificateMetadata(cert config.ManagedCertificate) string {
	var b strings.Builder
	b.WriteString("{\n")
	b.WriteString(fmt.Sprintf("  \"id\": %q,\n", cert.ID))
	b.WriteString(fmt.Sprintf("  \"domains\": %q,\n", strings.Join(cert.Domains, ",")))
	b.WriteString(fmt.Sprintf("  \"certFile\": %q,\n", cert.CertFile))
	b.WriteString(fmt.Sprintf("  \"keyFile\": %q,\n", cert.KeyFile))
	b.WriteString(fmt.Sprintf("  \"chainFile\": %q,\n", cert.ChainFile))
	b.WriteString(fmt.Sprintf("  \"fullChainFile\": %q,\n", cert.FullChainFile))
	b.WriteString(fmt.Sprintf("  \"ownerService\": %q,\n", cert.OwnerService))
	b.WriteString(fmt.Sprintf("  \"renewHook\": %q\n", cert.RenewHook))
	b.WriteString("}\n")
	return b.String()
}

func renderCertbotDeployHook(store config.CertificateStore) string {
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\nset -euo pipefail\n")
	seen := map[string]struct{}{}
	for _, cert := range store.Certificates {
		if cert.RenewHook != "" {
			b.WriteString(cert.RenewHook + "\n")
		}
		if cert.OwnerService != "" {
			seen[cert.OwnerService] = struct{}{}
		}
	}
	for _, cert := range store.LetsEncrypt.Certificates {
		if cert.DeployHook != "" {
			continue
		}
		managedName := cert.ID + ".service"
		if strings.HasPrefix(cert.ID, "las-") {
			seen[managedName] = struct{}{}
		}
	}
	for service := range seen {
		b.WriteString("systemctl try-reload-or-restart " + shellQuote(service) + " || true\n")
	}
	return b.String()
}

func openVPNProfilePath(tunnel config.Tunnel) string {
	if tunnel.Direction == "server" {
		return "/etc/openvpn/server/" + tunnel.ID + ".conf"
	}
	return "/etc/openvpn/client/" + tunnel.ID + ".conf"
}

func generatedOpenVPNAuthPath(tunnel config.Tunnel) string {
	if tunnel.Credentials["authFile"] != "" {
		return ""
	}
	if tunnel.Credentials["username"] != "" && tunnel.Credentials["password"] != "" {
		return "/etc/las/openvpn/" + tunnel.ID + ".auth"
	}
	return ""
}

func openVPNAuthPath(tunnel config.Tunnel) string {
	if tunnel.Credentials["authFile"] != "" {
		return tunnel.Credentials["authFile"]
	}
	return generatedOpenVPNAuthPath(tunnel)
}

func renderOpenVPNConfig(tunnel config.Tunnel) string {
	var b strings.Builder
	proto := optionDefault(tunnel.Options, "proto", "udp")
	port := optionDefault(tunnel.Options, "port", "1194")
	host, endpointPort := endpointHostPort(tunnel.RemoteEndpoint)
	if endpointPort != "" {
		port = endpointPort
	}
	b.WriteString("# Managed by LAS.\n")
	b.WriteString("dev " + tunnel.InterfaceName + "\n")
	if devType := tunnel.Options["devType"]; devType != "" {
		b.WriteString("dev-type " + devType + "\n")
	}
	b.WriteString("proto " + proto + "\n")
	b.WriteString("port " + port + "\n")
	b.WriteString("topology subnet\npersist-key\npersist-tun\n")
	if tunnel.MTU > 0 {
		b.WriteString("tun-mtu " + strconv.Itoa(tunnel.MTU) + "\n")
	}
	if tunnel.Direction == "server" {
		b.WriteString("mode server\ntls-server\n")
		if serverNet := tunnel.Options["server"]; serverNet != "" {
			b.WriteString("server " + serverNet + "\n")
		}
		if pool := tunnel.Options["ifconfigPool"]; pool != "" {
			b.WriteString("ifconfig-pool " + pool + "\n")
		}
		if ccd := tunnel.Options["clientConfigDir"]; ccd != "" {
			b.WriteString("client-config-dir " + ccd + "\n")
		}
		for _, route := range optionList(tunnel.Options["pushRoutes"]) {
			b.WriteString("push \"route " + route + "\"\n")
		}
		for _, dns := range tunnel.DNS {
			b.WriteString("push \"dhcp-option DNS " + dns + "\"\n")
		}
	} else {
		b.WriteString("client\nnobind\nremote-cert-tls server\n")
		if host != "" {
			b.WriteString("remote " + host + " " + port + "\n")
		}
		if authPath := openVPNAuthPath(tunnel); authPath != "" {
			b.WriteString("auth-user-pass " + authPath + "\n")
		}
		if boolOption(tunnel.Options["routeNoPull"]) {
			b.WriteString("route-nopull\n")
		}
		if boolOption(tunnel.Options["redirectGateway"]) {
			b.WriteString("redirect-gateway def1\n")
		}
	}
	for _, route := range optionList(tunnel.Options["routes"]) {
		b.WriteString("route " + route + "\n")
	}
	if value := tunnel.Options["ifconfig"]; value != "" {
		b.WriteString("ifconfig " + value + "\n")
	}
	writeOpenVPNCredential(&b, "ca", tunnel.Credentials["caFile"])
	writeOpenVPNCredential(&b, "cert", tunnel.Credentials["certFile"])
	writeOpenVPNCredential(&b, "key", tunnel.Credentials["keyFile"])
	writeOpenVPNCredential(&b, "pkcs12", tunnel.Credentials["pkcs12File"])
	writeOpenVPNCredential(&b, "dh", tunnel.Credentials["dhFile"])
	writeOpenVPNCredential(&b, "tls-crypt", tunnel.Credentials["tlsCryptFile"])
	writeOpenVPNCredential(&b, "tls-auth", tunnel.Credentials["tlsAuthFile"])
	for _, key := range []string{"cipher", "dataCiphers", "auth", "compress", "management"} {
		if value := tunnel.Options[key]; value != "" {
			b.WriteString(openVPNOptionName(key) + " " + value + "\n")
		}
	}
	verb := optionDefault(tunnel.Options, "verb", "3")
	b.WriteString("verb " + verb + "\n")
	b.WriteString("setenv LAS_TUNNEL_ID " + tunnel.ID + "\n")
	return b.String()
}

func writeOpenVPNCredential(b *strings.Builder, directive, value string) {
	if value != "" {
		b.WriteString(directive + " " + value + "\n")
	}
}

func openVPNOptionName(key string) string {
	switch key {
	case "dataCiphers":
		return "data-ciphers"
	default:
		return key
	}
}

func openConnectProtocol(tunnelType string, options map[string]string) string {
	if options["protocol"] != "" {
		return options["protocol"]
	}
	switch tunnelType {
	case "globalprotect":
		return "gp"
	case "pulse-secure":
		return "pulse"
	default:
		return "anyconnect"
	}
}

func renderOpenConnectEnv(tunnel config.Tunnel, protocol string) string {
	script := optionDefault(tunnel.Options, "script", "/etc/vpnc/vpnc-script")
	extra := []string{}
	if serverCert := tunnel.Options["serverCert"]; serverCert != "" {
		extra = append(extra, "--servercert", serverCert)
	}
	if caFile := tunnel.Credentials["caFile"]; caFile != "" {
		extra = append(extra, "--cafile", caFile)
	}
	if csdWrapper := tunnel.Options["csdWrapper"]; csdWrapper != "" {
		extra = append(extra, "--csd-wrapper", csdWrapper)
	}
	return strings.Join([]string{
		systemdEnvLine("VPN_SERVER", tunnel.RemoteEndpoint),
		systemdEnvLine("VPN_PROTOCOL", protocol),
		systemdEnvLine("VPN_INTERFACE", tunnel.InterfaceName),
		systemdEnvLine("VPN_SCRIPT", script),
		systemdEnvLine("VPN_USER", tunnel.Credentials["username"]),
		systemdEnvLine("PASSWORD_FILE", tunnel.Credentials["passwordFile"]),
		systemdEnvLine("COOKIE_FILE", tunnel.Credentials["cookieFile"]),
		systemdEnvLine("EXTRA_ARGS", joinArgs(extra)),
	}, "")
}

func renderOpenConnectService(envPath string) string {
	return "[Unit]\n" +
		"Description=LAS OpenConnect VPN tunnel\n" +
		"After=network-online.target\nWants=network-online.target\n\n" +
		"[Service]\n" +
		"Type=simple\n" +
		"EnvironmentFile=" + envPath + "\n" +
		"ExecStart=/bin/sh -c 'if [ -n \"${COOKIE_FILE:-}\" ]; then exec /usr/sbin/openconnect $EXTRA_ARGS --protocol \"$VPN_PROTOCOL\" --interface \"$VPN_INTERFACE\" --script \"$VPN_SCRIPT\" --user \"$VPN_USER\" --cookie-on-stdin \"$VPN_SERVER\" < \"$COOKIE_FILE\"; elif [ -n \"${PASSWORD_FILE:-}\" ]; then exec /usr/sbin/openconnect $EXTRA_ARGS --protocol \"$VPN_PROTOCOL\" --interface \"$VPN_INTERFACE\" --script \"$VPN_SCRIPT\" --user \"$VPN_USER\" --passwd-on-stdin \"$VPN_SERVER\" < \"$PASSWORD_FILE\"; else exec /usr/sbin/openconnect $EXTRA_ARGS --protocol \"$VPN_PROTOCOL\" --interface \"$VPN_INTERFACE\" --script \"$VPN_SCRIPT\" --user \"$VPN_USER\" \"$VPN_SERVER\"; fi'\n" +
		"Restart=always\nRestartSec=5s\n\n" +
		"[Install]\nWantedBy=multi-user.target\n"
}

func renderFortiGateSSLConfig(tunnel config.Tunnel) string {
	host, port := endpointHostPort(tunnel.RemoteEndpoint)
	if port == "" {
		port = optionDefault(tunnel.Options, "port", "443")
	}
	var b strings.Builder
	b.WriteString("# Managed by LAS.\n")
	b.WriteString("host = " + host + "\n")
	b.WriteString("port = " + port + "\n")
	if username := tunnel.Credentials["username"]; username != "" {
		b.WriteString("username = " + username + "\n")
	}
	if password := tunnel.Credentials["password"]; password != "" {
		b.WriteString("password = " + password + "\n")
	}
	if trusted := tunnel.Options["trustedCert"]; trusted != "" {
		b.WriteString("trusted-cert = " + trusted + "\n")
	}
	if caFile := tunnel.Credentials["caFile"]; caFile != "" {
		b.WriteString("ca-file = " + caFile + "\n")
	}
	if tunnel.InterfaceName != "" {
		b.WriteString("pppd-ifname = " + tunnel.InterfaceName + "\n")
	}
	if tunnel.Options["setDNS"] != "" {
		b.WriteString("set-dns = " + tunnel.Options["setDNS"] + "\n")
	}
	if tunnel.Options["realm"] != "" {
		b.WriteString("realm = " + tunnel.Options["realm"] + "\n")
	}
	return b.String()
}

func renderFortiGateSSLService(tunnel config.Tunnel, confPath string) string {
	args := "/usr/bin/openfortivpn -c " + shellQuote(confPath)
	if passwordFile := tunnel.Credentials["passwordFile"]; passwordFile != "" {
		args += " --password-file=" + shellQuote(passwordFile)
	}
	return "[Unit]\n" +
		"Description=LAS FortiGate SSL VPN tunnel\n" +
		"After=network-online.target\nWants=network-online.target\n\n" +
		"[Service]\n" +
		"Type=simple\n" +
		"ExecStart=" + args + "\n" +
		"Restart=always\nRestartSec=5s\n\n" +
		"[Install]\nWantedBy=multi-user.target\n"
}

func renderProxyTunnelService(engine string, tunnel config.Tunnel, configFile string) string {
	binary := "/usr/local/bin/" + engine
	if override := tunnel.Options["binary"]; override != "" {
		binary = override
	}
	args := "run -c " + shellQuote(configFile)
	if engine == "xray" {
		args = "run -config " + shellQuote(configFile)
	}
	return "[Unit]\n" +
		"Description=LAS " + engine + " tunnel " + tunnel.ID + "\n" +
		"After=network-online.target\nWants=network-online.target\n\n" +
		"[Service]\n" +
		"Type=simple\n" +
		"ExecStart=" + binary + " " + args + "\n" +
		"Restart=always\nRestartSec=5s\nLimitNOFILE=1048576\n\n" +
		"[Install]\nWantedBy=multi-user.target\n"
}

func endpointHostPort(endpoint string) (string, string) {
	value := strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
	if idx := strings.IndexByte(value, '/'); idx >= 0 {
		value = value[:idx]
	}
	if strings.Count(value, ":") == 1 {
		parts := strings.SplitN(value, ":", 2)
		return parts[0], parts[1]
	}
	return strings.Trim(value, "[]"), ""
}

func optionDefault(options map[string]string, key, fallback string) string {
	if value := options[key]; value != "" {
		return value
	}
	return fallback
}

func optionList(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n'
	})
	out := []string{}
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func boolOption(value string) bool {
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func systemdEnvLine(key, value string) string {
	return key + "=" + strconv.Quote(value) + "\n"
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

func joinArgs(args []string) string {
	parts := append([]string{}, args...)
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
		switch services.DNSServer.Engine {
		case "", "dnsmasq":
			plan.AddWrite("render dnsmasq service profile", "/etc/dnsmasq.d/las-services.conf", "0644", renderDNSMasqServiceConfig(cfg))
			plan.AddCommand("enable dnsmasq for DHCP/DNS", "systemctl", "enable", "--now", "dnsmasq")
		case "unbound":
			if services.DHCPServer.Enabled {
				plan.AddWrite("render dnsmasq DHCP-only profile", "/etc/dnsmasq.d/las-dhcp.conf", "0644", renderDNSMasqServiceConfig(cfg))
				plan.AddCommand("enable dnsmasq for DHCP", "systemctl", "enable", "--now", "dnsmasq")
			}
			plan.AddWrite("render unbound DNS server profile", "/etc/unbound/unbound.conf.d/las.conf", "0644", renderUnboundConfig(services.DNSServer))
			plan.AddCommand("enable unbound DNS server", "systemctl", "enable", "--now", "unbound")
		case "bind":
			if services.DHCPServer.Enabled {
				plan.AddWrite("render dnsmasq DHCP-only profile", "/etc/dnsmasq.d/las-dhcp.conf", "0644", renderDNSMasqServiceConfig(cfg))
				plan.AddCommand("enable dnsmasq for DHCP", "systemctl", "enable", "--now", "dnsmasq")
			}
			plan.AddWrite("render BIND local zone include", "/etc/bind/named.conf.las", "0644", renderBINDConfig(services.DNSServer))
			plan.AddCommand("enable BIND DNS server", "systemctl", "enable", "--now", "bind9")
			plan.AddWarning("BIND profile is rendered as /etc/bind/named.conf.las; include it from named.conf.local before relying on it")
		}
	}
	if services.DHCPClient.Enabled {
		plan.AddWarning("DHCP client is modeled on interfaces %s; use systemd-networkd, NetworkManager, or dhclient renderer TODO", strings.Join(services.DHCPClient.Interfaces, ","))
	}
	if services.DNSClient.Enabled {
		if services.DNSClient.UseSystemdResolved {
			plan.AddCommand("ensure systemd-resolved config directory", "install", "-d", "-m", "0755", "/etc/systemd/resolved.conf.d")
			plan.AddWrite("render systemd-resolved DNS client profile", "/etc/systemd/resolved.conf.d/las.conf", "0644", renderResolvedConfig(services.DNSClient))
			plan.AddCommand("enable systemd-resolved DNS client", "systemctl", "enable", "--now", "systemd-resolved")
		}
		if services.DNSClient.WriteResolvConf {
			plan.AddWrite("render resolv.conf DNS client profile", "/etc/resolv.conf", "0644", renderResolvConf(services.DNSClient))
		}
	}
	if services.NTPServer.Enabled || services.NTPClient.Enabled {
		switch services.NTPServer.Engine {
		case "", "chrony":
			plan.AddWrite("render chrony profile", "/etc/chrony/conf.d/las.conf", "0644", renderChronyConfig(services.NTPServer, services.NTPClient))
			plan.AddCommand("enable chrony", "systemctl", "enable", "--now", "chrony")
		case "ntpd":
			plan.AddWrite("render ntpsec profile", "/etc/ntpsec/ntp.conf", "0644", renderNTPDConfig(services.NTPServer, services.NTPClient))
			plan.AddCommand("enable ntpsec", "systemctl", "enable", "--now", "ntpsec")
		}
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

func renderDNSMasqServiceConfig(cfg config.Config) string {
	var b strings.Builder
	b.WriteString("# Managed by LAS.\n")
	if cfg.Services.DNSServer.Enabled {
		b.WriteString("domain-needed\nbogus-priv\n")
		if cfg.Services.DNSServer.RebindProtection {
			b.WriteString("stop-dns-rebind\n")
		}
		if cfg.Services.DNSServer.StrictOrder {
			b.WriteString("strict-order\n")
		}
		if cfg.Services.DNSServer.DNSSEC {
			b.WriteString("dnssec\ntrust-anchor=.,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n")
		}
		if cfg.Services.DNSServer.BindInterfaces {
			b.WriteString("bind-interfaces\n")
		}
		if cfg.Services.DNSServer.CacheSize > 0 {
			b.WriteString("cache-size=" + strconv.Itoa(cfg.Services.DNSServer.CacheSize) + "\n")
		}
		for _, iface := range cfg.Services.DNSServer.Listen {
			b.WriteString("interface=" + iface + "\n")
		}
		for _, address := range cfg.Services.DNSServer.ListenAddresses {
			b.WriteString("listen-address=" + address + "\n")
		}
		if len(cfg.Services.DNSServer.Forwarders) > 0 {
			b.WriteString("no-resolv\n")
		}
		for _, forwarder := range cfg.Services.DNSServer.Forwarders {
			b.WriteString("server=" + forwarder + "\n")
		}
		for _, zone := range cfg.Services.DNSServer.ConditionalForwarders {
			for _, upstream := range zone.Upstreams {
				b.WriteString("server=/" + zone.Domain + "/" + upstream + "\n")
			}
		}
		for _, domain := range cfg.Services.DNSServer.LocalDomains {
			b.WriteString("local=/" + domain + "/\n")
		}
		for _, override := range cfg.Services.DNSServer.AddressOverrides {
			b.WriteString("address=/" + override.Domain + "/" + override.Address + "\n")
		}
		for _, record := range cfg.Services.DNSServer.Records {
			b.WriteString(renderDNSMasqRecord(record))
		}
	}
	if cfg.Services.DHCPServer.Enabled {
		if cfg.Services.DHCPServer.Authoritative {
			b.WriteString("dhcp-authoritative\n")
		}
		if cfg.Services.DHCPServer.LeaseFile != "" {
			b.WriteString("dhcp-leasefile=" + cfg.Services.DHCPServer.LeaseFile + "\n")
		}
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
		for _, lease := range cfg.Services.DHCPServer.StaticLeases {
			values := []string{lease.MAC}
			if lease.IP != "" {
				values = append(values, lease.IP)
			}
			if lease.Hostname != "" {
				values = append(values, lease.Hostname)
			}
			if lease.Lease != "" {
				values = append(values, lease.Lease)
			}
			b.WriteString("dhcp-host=" + strings.Join(values, ",") + "\n")
		}
		for _, option := range cfg.Services.DHCPServer.Options {
			prefix := "dhcp-option="
			if option.Tag != "" {
				prefix += "tag:" + option.Tag + ","
			}
			b.WriteString(prefix + option.Code + "," + option.Value + "\n")
		}
	}
	return b.String()
}

func renderChronyConfig(server config.NTPServiceConfig, client config.NTPClientConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by LAS.\n")
	if client.Makestep {
		b.WriteString("makestep 1.0 3\n")
	}
	for _, upstream := range client.Servers {
		b.WriteString("server " + upstream + " iburst" + ntsSuffix(client.NTS) + "\n")
	}
	for _, upstream := range client.Pools {
		b.WriteString("pool " + upstream + " iburst" + ntsSuffix(client.NTS) + "\n")
	}
	for _, upstream := range client.Peers {
		b.WriteString("peer " + upstream + " iburst\n")
	}
	for _, upstream := range client.FallbackServers {
		b.WriteString("server " + upstream + " iburst prefer\n")
	}
	if server.Enabled {
		for _, iface := range server.Listen {
			b.WriteString("# serve NTP on " + iface + "\n")
		}
		for _, cidr := range server.AllowCIDRs {
			b.WriteString("allow " + cidr + "\n")
		}
		stratum := server.LocalStratum
		if stratum == 0 {
			stratum = 10
		}
		b.WriteString("local stratum " + strconv.Itoa(stratum) + "\n")
		if server.NTS.Enabled {
			b.WriteString("ntsservercert " + server.NTS.CertFile + "\n")
			b.WriteString("ntsserverkey " + server.NTS.KeyFile + "\n")
		}
	}
	return b.String()
}

func renderDNSMasqRecord(record config.DNSRecord) string {
	recordType := strings.ToUpper(record.Type)
	switch recordType {
	case "", "A", "AAAA":
		return "host-record=" + record.Name + "," + record.Value + "\n"
	case "CNAME":
		return "cname=" + record.Name + "," + record.Value + "\n"
	case "TXT":
		return "txt-record=" + record.Name + "," + record.Value + "\n"
	case "MX":
		return "mx-host=" + record.Name + "," + record.Value + "\n"
	case "SRV":
		return "srv-host=" + record.Name + "," + record.Value + "\n"
	case "PTR":
		return "ptr-record=" + record.Name + "," + record.Value + "\n"
	default:
		return "# unsupported-record=" + record.Name + "," + record.Type + "," + record.Value + "\n"
	}
}

func renderUnboundConfig(dns config.DNSServiceConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by LAS.\nserver:\n")
	if dns.CacheSize > 0 {
		b.WriteString("  msg-cache-size: " + strconv.Itoa(dns.CacheSize) + "m\n")
		b.WriteString("  rrset-cache-size: " + strconv.Itoa(dns.CacheSize*2) + "m\n")
	}
	if dns.DNSSEC {
		b.WriteString("  auto-trust-anchor-file: \"/var/lib/unbound/root.key\"\n")
	}
	if dns.RebindProtection {
		b.WriteString("  private-address: 10.0.0.0/8\n  private-address: 172.16.0.0/12\n  private-address: 192.168.0.0/16\n")
	}
	for _, iface := range dns.Listen {
		b.WriteString("  # listen interface: " + iface + "\n")
	}
	if len(dns.ListenAddresses) == 0 {
		b.WriteString("  interface: 0.0.0.0\n")
	} else {
		for _, address := range dns.ListenAddresses {
			b.WriteString("  interface: " + address + "\n")
		}
	}
	for _, domain := range dns.LocalDomains {
		b.WriteString("  local-zone: \"" + domain + ".\" static\n")
	}
	for _, override := range dns.AddressOverrides {
		b.WriteString("  local-data: \"" + override.Domain + " A " + override.Address + "\"\n")
	}
	for _, record := range dns.Records {
		b.WriteString("  local-data: \"" + record.Name + " " + strings.ToUpper(record.Type) + " " + record.Value + "\"\n")
	}
	if len(dns.Forwarders) > 0 {
		b.WriteString("forward-zone:\n  name: \".\"\n")
		for _, forwarder := range dns.Forwarders {
			b.WriteString("  forward-addr: " + forwarder + "\n")
		}
	}
	for _, zone := range dns.ConditionalForwarders {
		b.WriteString("forward-zone:\n  name: \"" + zone.Domain + ".\"\n")
		for _, upstream := range zone.Upstreams {
			b.WriteString("  forward-addr: " + upstream + "\n")
		}
	}
	return b.String()
}

func renderBINDConfig(dns config.DNSServiceConfig) string {
	var b strings.Builder
	b.WriteString("// Managed by LAS. Include this file from /etc/bind/named.conf.local.\n")
	b.WriteString("options {\n")
	if len(dns.Forwarders) > 0 {
		b.WriteString("  forwarders {\n")
		for _, forwarder := range dns.Forwarders {
			b.WriteString("    " + forwarder + ";\n")
		}
		b.WriteString("  };\n  forward only;\n")
	}
	if len(dns.ListenAddresses) > 0 {
		b.WriteString("  listen-on { ")
		for _, address := range dns.ListenAddresses {
			b.WriteString(address + "; ")
		}
		b.WriteString("};\n")
	}
	if dns.DNSSEC {
		b.WriteString("  dnssec-validation auto;\n")
	}
	b.WriteString("};\n")
	for _, zone := range dns.ConditionalForwarders {
		b.WriteString("zone \"" + zone.Domain + "\" { type forward; forwarders { ")
		for _, upstream := range zone.Upstreams {
			b.WriteString(upstream + "; ")
		}
		b.WriteString("}; };\n")
	}
	if len(dns.Records) > 0 || len(dns.AddressOverrides) > 0 {
		b.WriteString("// Static local records are modeled; generate zone files per domain before production BIND use.\n")
	}
	return b.String()
}

func renderResolvedConfig(client config.DNSClientConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by LAS.\n[Resolve]\n")
	if len(client.Resolvers) > 0 {
		b.WriteString("DNS=" + strings.Join(client.Resolvers, " ") + "\n")
	}
	if len(client.FallbackResolvers) > 0 {
		b.WriteString("FallbackDNS=" + strings.Join(client.FallbackResolvers, " ") + "\n")
	}
	if len(client.Search) > 0 {
		b.WriteString("Domains=" + strings.Join(client.Search, " ") + "\n")
	}
	if client.DNSOverTLS {
		b.WriteString("DNSOverTLS=yes\n")
	}
	if client.DNSSEC != "" {
		b.WriteString("DNSSEC=" + client.DNSSEC + "\n")
	}
	return b.String()
}

func renderResolvConf(client config.DNSClientConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by LAS.\n")
	for _, resolver := range client.Resolvers {
		b.WriteString("nameserver " + resolverNameServer(resolver) + "\n")
	}
	if len(client.Search) > 0 {
		b.WriteString("search " + strings.Join(client.Search, " ") + "\n")
	}
	return b.String()
}

func renderNTPDConfig(server config.NTPServiceConfig, client config.NTPClientConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by LAS.\n")
	for _, upstream := range client.Servers {
		b.WriteString("server " + upstream + " iburst\n")
	}
	for _, upstream := range client.Pools {
		b.WriteString("pool " + upstream + " iburst\n")
	}
	for _, upstream := range client.Peers {
		b.WriteString("peer " + upstream + " iburst\n")
	}
	for _, upstream := range client.FallbackServers {
		b.WriteString("server " + upstream + " iburst prefer\n")
	}
	b.WriteString("restrict default kod nomodify nopeer noquery limited\nrestrict 127.0.0.1\nrestrict ::1\n")
	if server.Enabled {
		for _, cidr := range server.AllowCIDRs {
			b.WriteString("# allow " + cidr + "\n")
		}
		stratum := server.LocalStratum
		if stratum == 0 {
			stratum = 10
		}
		b.WriteString("tos orphan " + strconv.Itoa(stratum) + "\n")
	}
	if client.NTS || server.NTS.Enabled {
		b.WriteString("# NTS is supported through chrony in LAS; ntpsec NTS rendering is intentionally conservative.\n")
	}
	return b.String()
}

func ntsSuffix(enabled bool) string {
	if enabled {
		return " nts"
	}
	return ""
}

func resolverNameServer(value string) string {
	cleaned := strings.TrimPrefix(value, "tls://")
	if strings.Contains(cleaned, "#") {
		cleaned = strings.SplitN(cleaned, "#", 2)[0]
	}
	if strings.Contains(cleaned, ":") && strings.Count(cleaned, ":") == 1 {
		return strings.SplitN(cleaned, ":", 2)[0]
	}
	return strings.Trim(cleaned, "[]")
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
