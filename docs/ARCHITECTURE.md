# Architecture

LAS is split into three layers:

1. Web UI: a static HTML/CSS/JavaScript application served by the daemon.
2. Control plane daemon: validates config, generates plans, and applies plans.
3. Dataplane tools: Linux kernel routing, nftables, and external VPN/security daemons.

## Why This Shape

Routers need stability more than cleverness. The daemon does not implement packet forwarding itself. Linux already has a fast kernel dataplane; established packages already implement VPNs, IPS, and antivirus scanning. The daemon owns orchestration and validation.

## Plan Lifecycle

1. Load JSON config.
2. Validate all referenced links, tunnel IDs, routes, actions, ports, CIDRs, marks, and tables.
3. Generate an ordered plan.
4. Preview the plan in the UI or CLI.
5. Execute it only when the daemon is started with `--apply`.

The plan consists of commands, file writes, and warnings. File writes are atomic. Commands are run without shell expansion except for small idempotent Linux snippets where the inputs are restricted by validation.

## Routing Model

Rules run in priority order. A rule has:

- Match fields: input/output link, source/destination CIDRs, source/destination ports, protocols, tunnel IDs, domains, GeoIP tags, route sets, and app/service labels.
- Action fields: direct, interface, tunnel, WAN group, blackhole, reject, scan, mirror.
- Optional mark/table overrides.

For tunnel and WAN-group actions, the plan uses nftables to set a Linux fwmark, then installs `ip rule` entries to route marked traffic through the selected table. WAN groups can render weighted ECMP or failover default routes.

Route sets are rendered as nftables interval sets when static CIDRs are present. Dynamic country, domain, and app/service sources are modeled now; a feed generator is still required to periodically resolve and normalize them into CIDRs.

## VPN Model

The project supports two tunnel classes:

- Kernel/device tunnels: generic TUN and WireGuard can be created directly.
- Service-backed tunnels: OpenVPN, IPsec/L2TP, VLESS, VMess, XHTTP, and custom tunnels are managed by their native daemons, and LAS routes traffic into the exposed interface or local TUN.

This keeps protocol-specific risk in maintained packages such as WireGuard, OpenVPN, strongSwan, Xray, or sing-box.

## Security Model

Firewall/NAT are rendered as nftables. IPS is integrated through Suricata in AF_PACKET or NFQUEUE mode. Antivirus is integrated through ClamAV profile generation for proxy/ICAP workflows.

Encrypted pass-through traffic cannot be antivirus-scanned without termination or endpoint cooperation. The UI and generated warnings make that explicit.
