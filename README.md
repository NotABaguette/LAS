# LAS

LAS is a small router appliance control plane for Debian. It provides:

- A configurable web UI for interfaces, tunnels, Geo/app/service route sets, WAN load balancing, services, diagnostics, firewall/NAT, IPS, and antivirus integration.
- A Go daemon that validates one JSON router model, generates an explicit apply plan, and can execute that plan on Debian.
- Integration points for proven dataplane tools instead of reimplementing VPN or packet inspection protocols in-process: `iproute2`, `nftables`, WireGuard, OpenVPN, strongSwan/IPsec, xl2tpd, Xray/sing-box style VLESS/VMess/XHTTP tunnels, dnsmasq, chrony, FRR/MPLS, Suricata, and ClamAV.

This repository is designed to become the management layer of a Debian router. It intentionally keeps dangerous operations behind `--apply`; by default the daemon previews plans without changing the host.

## Quick Start

```bash
cd ~/Documents/Projects/las
go test ./...
go run ./cmd/lasd --config ./configs/router.example.json --web-dir ./web
```

Open `http://127.0.0.1:8088`.

To preview the system changes:

```bash
go run ./cmd/lasd --config ./configs/router.example.json --plan
```

To allow the web UI/API to execute changes on a Debian host:

```bash
sudo ./lasd --config /etc/las/router.json --web-dir /usr/share/las/web --apply
```

## Debian Install

On the target Debian router:

```bash
sudo ./scripts/install.sh
sudo systemctl enable --now lasd
```

The installer creates:

- `/etc/las/router.json`
- `/usr/local/sbin/lasd`
- `/usr/share/las/web`
- `/usr/local/sbin/las-update`
- `/usr/local/sbin/las-update-cores`
- `las-updater.timer`
- `lasd.service`

## Configuration Model

All state lives in one JSON file. The major sections are:

- `interfaces`: WAN, LAN, management, DMZ, and tunnel-facing interfaces.
- `tunnels`: inbound, outbound, or peer WireGuard, OpenVPN, IPsec/L2TP, generic TUN, VLESS, VMess, XHTTP, and custom service-backed tunnels.
- `routing.sets`: Geo/app/service route sets, such as Iran destination IPs, Telegram CIDRs, or WhatsApp CIDRs.
- `routing.wanGroups`: weighted ECMP or failover WAN/SD-WAN groups.
- `routing.staticRoutes`: deterministic route entries per table.
- `routing.rules`: ordered policy rules matching input interface, source/destination CIDR, port ranges, protocol, domain tags, GeoIP tags, route sets, app/service labels, or tunnel metadata, then routing to an interface, tunnel, WAN group, direct path, blackhole, reject, scan, or mirror target.
- `services`: DHCP server/client, DNS server/client, NTP server/client, and MPLS model.
- `security`: firewall, NAT, port forwarding, management access, Suricata IPS, ClamAV integration, and DNS filtering.

See [configs/router.example.json](configs/router.example.json).

## Current Tunnel Support

The current model supports these tunnel types:

- Direct Linux/device-backed: `tun`, `wireguard`, `gre`, `gretap`, `ipip`, `sit`, `6to4`, `ip6gre`, `ip6tnl`, `vti`, `ipsec-vti`, `vxlan`, `erspan`.
- Service-backed VPNs: `openvpn`, `ipsec`, `l2tp`, `l2tp-ipsec`, `pptp`, `sstp`, `pppoe`, `l2tpv3`, `eoip`, `tailscale`, `zerotier`, `custom`.
- Proxy/TUN engines: `vless`, `vmess`, `vless-xhttp`, `xhttp`, `xray`, `sing-box`.

See [docs/ROUTEROS_TODO.md](docs/ROUTEROS_TODO.md) for the RouterOS-style parity matrix.

## Automatic Updates

The installer enables `las-updater.timer`. The timer runs `/usr/local/sbin/las-update`, which:

- Runs Debian package update/upgrade when enabled in `/etc/default/las-updater`.
- Updates ClamAV signatures with `freshclam` when available.
- Downloads the latest Xray-core release from `XTLS/Xray-core`.
- Downloads the latest sing-box release from `SagerNet/sing-box`.
- Installs matching Linux architecture binaries atomically into `/usr/local/bin`.

Control updater behavior in `/etc/default/las-updater`. Preview core updates manually:

```bash
sudo /usr/local/sbin/las-update-cores --dry-run
```

## Safety Notes

- Run the daemon bound to `127.0.0.1` until authentication/TLS and your management network are configured.
- Keep SSH or serial access during early deployments. A bad route/firewall policy can cut off the web UI.
- Automated full package upgrades can affect router stability. Disable `LAS_APT_UPGRADE` in `/etc/default/las-updater` if you want security-only/manual package maintenance.
- Antivirus cannot inspect encrypted traffic unless traffic is terminated or proxied. The ClamAV integration is designed for proxy/ICAP workflows and file streams, not impossible transparent decryption.
- VLESS/VMess/XHTTP are handled through external engines such as Xray or sing-box that create a TUN device or local proxy. This daemon routes traffic into those interfaces/services.

## Build

```bash
go build -o lasd ./cmd/lasd
```

## Roadmap

- Add persistent audit log storage.
- Add user authentication and role separation.
- Add package-specific template rendering for strongSwan, xl2tpd, OpenVPN, Xray, sing-box, Suricata, and ClamAV.
- Add transactional rollback using a watchdog route and nftables checkpoint restore.
- Add route feed download/normalization for GeoIP, Telegram, WhatsApp, and other app/service CIDR sets.
- Track RouterOS-style feature parity in [docs/ROUTEROS_TODO.md](docs/ROUTEROS_TODO.md).
