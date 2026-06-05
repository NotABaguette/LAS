# Debian Router

Debian Router is a small router appliance control plane for Debian. It provides:

- A configurable web UI for interfaces, tunnels, policy routing, static routes, firewall/NAT, IPS, and antivirus integration.
- A Go daemon that validates one JSON router model, generates an explicit apply plan, and can execute that plan on Debian.
- Integration points for proven dataplane tools instead of reimplementing VPN or packet inspection protocols in-process: `iproute2`, `nftables`, WireGuard, OpenVPN, strongSwan/IPsec, xl2tpd, Xray/sing-box style VLESS/VMess/XHTTP tunnels, Suricata, and ClamAV.

This repository is designed to become the management layer of a Debian router. It intentionally keeps dangerous operations behind `--apply`; by default the daemon previews plans without changing the host.

## Quick Start

```bash
cd ~/Documents/Projects/debian-router
go test ./...
go run ./cmd/debian-routerd --config ./configs/router.example.json --web-dir ./web
```

Open `http://127.0.0.1:8088`.

To preview the system changes:

```bash
go run ./cmd/debian-routerd --config ./configs/router.example.json --plan
```

To allow the web UI/API to execute changes on a Debian host:

```bash
sudo ./debian-routerd --config /etc/debian-router/router.json --web-dir /usr/share/debian-router/web --apply
```

## Debian Install

On the target Debian router:

```bash
sudo ./scripts/install.sh
sudo systemctl enable --now debian-routerd
```

The installer creates:

- `/etc/debian-router/router.json`
- `/usr/local/sbin/debian-routerd`
- `/usr/share/debian-router/web`
- `debian-routerd.service`

## Configuration Model

All state lives in one JSON file. The major sections are:

- `interfaces`: WAN, LAN, management, DMZ, and tunnel-facing interfaces.
- `tunnels`: WireGuard, OpenVPN, IPsec/L2TP, generic TUN, VLESS, VMess, XHTTP, and custom service-backed tunnels.
- `routing.staticRoutes`: deterministic route entries per table.
- `routing.rules`: ordered policy rules matching input interface, source/destination CIDR, port ranges, protocol, domain tags, GeoIP tags, or tunnel metadata, then routing to an interface, tunnel, direct path, blackhole, reject, scan, or mirror target.
- `security`: firewall, NAT, management access, Suricata IPS, ClamAV integration, and DNS filtering.

See [configs/router.example.json](configs/router.example.json).

## Current Tunnel Support

The current model supports these tunnel types:

- Direct Linux/device-backed: `tun`, `wireguard`, `gre`, `gretap`, `ipip`, `sit`, `6to4`, `ip6gre`, `ip6tnl`, `vti`, `ipsec-vti`, `vxlan`, `erspan`.
- Service-backed VPNs: `openvpn`, `ipsec`, `l2tp`, `l2tp-ipsec`, `pptp`, `sstp`, `pppoe`, `l2tpv3`, `eoip`, `tailscale`, `zerotier`, `custom`.
- Proxy/TUN engines: `vless`, `vmess`, `vless-xhttp`, `xhttp`, `xray`, `sing-box`.

See [docs/ROUTEROS_TODO.md](docs/ROUTEROS_TODO.md) for the RouterOS-style parity matrix.

## Safety Notes

- Run the daemon bound to `127.0.0.1` until authentication/TLS and your management network are configured.
- Keep SSH or serial access during early deployments. A bad route/firewall policy can cut off the web UI.
- Antivirus cannot inspect encrypted traffic unless traffic is terminated or proxied. The ClamAV integration is designed for proxy/ICAP workflows and file streams, not impossible transparent decryption.
- VLESS/VMess/XHTTP are handled through external engines such as Xray or sing-box that create a TUN device or local proxy. This daemon routes traffic into those interfaces/services.

## Build

```bash
go build -o debian-routerd ./cmd/debian-routerd
```

## Roadmap

- Add persistent audit log storage.
- Add user authentication and role separation.
- Add package-specific template rendering for strongSwan, xl2tpd, OpenVPN, Xray, sing-box, Suricata, and ClamAV.
- Add transactional rollback using a watchdog route and nftables checkpoint restore.
- Track RouterOS-style feature parity in [docs/ROUTEROS_TODO.md](docs/ROUTEROS_TODO.md).
