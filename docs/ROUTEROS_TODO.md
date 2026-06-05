# RouterOS Parity TODO

This project should aim for RouterOS-style breadth while staying Debian/Linux-native. The target is not to clone RouterOS internals; it is to provide an intuitive control plane over Linux kernel networking, nftables, FRR, VPN daemons, and security tools.

Status legend:

- `done`: modeled and plan-rendered.
- `partial`: modeled, with service-backed or warning-only apply support.
- `todo`: not implemented yet.

## VPN And Tunnel Matrix

| Feature | Status | Debian/Linux implementation target |
| --- | --- | --- |
| Generic TUN | done | `ip tuntap` |
| WireGuard | done | `wireguard-tools`, `wg setconf` |
| GRE | done | `ip tunnel mode gre` |
| GRETAP | done | `ip link type gretap` |
| IPIP | done | `ip tunnel mode ipip` |
| SIT / 6to4 | done | `ip tunnel mode sit` |
| VTI / IPsec VTI | done | `ip tunnel mode vti` plus strongSwan policy |
| VXLAN | done | `ip link type vxlan` |
| ERSPAN | done | `ip link type erspan` |
| OpenVPN | partial | `openvpn-client@.service`, full profile renderer TODO |
| IPsec IKEv1/IKEv2 | partial | strongSwan, full peer/proposal/secret renderer TODO |
| L2TP | partial | `xl2tpd`, full PPP profile renderer TODO |
| L2TP/IPsec | partial | strongSwan plus `xl2tpd`, full renderer TODO |
| PPTP | partial | PPP service-backed; legacy/insecure warning TODO |
| SSTP | partial | PPP/SSTP service-backed; full renderer TODO |
| PPPoE client/server | partial | PPP/accel-ppp or rp-pppoe renderer TODO |
| L2TPv3 pseudowire | partial | `ip l2tp`, full session renderer TODO |
| EoIP | partial | RouterOS GRE-based L2 tunnel; map to GRETAP/VXLAN or external EoIP-compatible daemon |
| VLESS | partial | Xray/sing-box service-backed |
| VMess | partial | Xray/sing-box service-backed |
| XHTTP transports | partial | Xray/sing-box service-backed |
| sing-box | partial | service-backed TUN/proxy |
| Xray | partial | service-backed TUN/proxy |
| Tailscale | partial | service-backed routing target |
| ZeroTier | partial | service-backed routing target |
| MPLS/VPLS | todo | FRR/MPLS kernel stack, design required |
| L2 bridging over VPN | todo | Linux bridge plus GRETAP/VXLAN/L2TPv3 profiles |
| Road-warrior VPN portal | todo | generated users, certs, QR/config export |
| Certificate authority | todo | local CA, ACME, strongSwan/OpenVPN cert lifecycle |
| Inbound/outbound tunnel mode | partial | direction is modeled; full server/client templates TODO |

## RouterOS-Style Feature Backlog

### Interfaces And L2

| Feature | Status | Notes |
| --- | --- | --- |
| Ethernet interface config | done | address, MTU, role, gateway modeled |
| VLANs | todo | Linux VLAN links, bridge VLAN filtering |
| Bridges | todo | Linux bridge, STP/RSTP, VLAN-aware bridge |
| Bonding/LACP | todo | `ip link type bond` |
| VRRP | todo | keepalived integration |
| DHCP client | partial | service model and interface `dhcp`; renderer TODO |
| DHCP server | partial | service model plus baseline dnsmasq profile |
| IPv6 SLAAC/DHCPv6/PD | todo | systemd-networkd/Kea integration |

### Routing

| Feature | Status | Notes |
| --- | --- | --- |
| Static routes | done | per-table route rendering |
| Policy routing | done | nft marks plus `ip rule` |
| Multiple routing tables | done | table fields on routes/tunnels/rules |
| GeoIP route sets | partial | static CIDRs render to nft sets; dynamic feed generator TODO |
| Application/service routing | partial | labels and route sets modeled; feed mapping TODO |
| WAN load balancing | partial | weighted ECMP/failover tables modeled and rendered |
| VRF-lite | todo | `ip link type vrf` |
| BGP | todo | FRR integration |
| OSPFv2/v3 | todo | FRR integration |
| RIP/RIPng | todo | FRR integration |
| BFD | todo | FRR integration |
| Route filters/maps | todo | FRR route-map UI |
| ECMP | partial | WAN group weighted route model |

### Firewall, NAT, And QoS

| Feature | Status | Notes |
| --- | --- | --- |
| Stateful firewall | done | nftables input/forward chains |
| NAT masquerade | done | nftables postrouting |
| Mangle/mark rules | done | nftables mark in prerouting |
| Reject/drop rules | done | nftables forward chain |
| Port forwarding / dstnat | done | nftables DNAT renderer |
| 1:1 NAT / netmap | todo | nftables SNAT/DNAT maps |
| Address lists | todo | nft sets |
| Domain/GeoIP matching | partial | modeled; route-set/feed generator TODO |
| Queues / bandwidth limits | todo | Linux `tc`, CAKE/FQ-CoDel/HTB |
| FastTrack equivalent | todo | flowtable/offload evaluation |
| UPnP | todo | miniupnpd integration |

### Security

| Feature | Status | Notes |
| --- | --- | --- |
| IPS | partial | Suricata AF_PACKET/NFQUEUE service integration |
| Antivirus | partial | ClamAV proxy/ICAP profile; transparent TLS scanning is not possible |
| DNS filtering | partial | dnsmasq profile skeleton |
| Threat feeds | todo | managed nft sets and Suricata rules |
| IDS dashboards | todo | event ingestion and UI |
| Captive portal / hotspot | todo | CoovaChilli/openNDS or custom portal |
| RADIUS/AAA | todo | FreeRADIUS integration |

### Services, Monitoring, And Automation

| Feature | Status | Notes |
| --- | --- | --- |
| Web UI | done | static SPA |
| Dry-run apply plans | done | commands/writes/warnings |
| System status probe | done | command/service availability |
| Diagnostics | partial | ping, traceroute, curl-head, dig, and route lookup API/UI |
| DNS server/client | partial | service model plus baseline dnsmasq/resolver config |
| NTP server/client | partial | service model plus baseline chrony config |
| MPLS | partial | service model plus FRR warning/enablement |
| Automatic updates | partial | daily system/core updater for apt, ClamAV, Xray-core, sing-box |
| Audit log | todo | persistent change and apply history |
| Rollback watchdog | todo | revert route/firewall if management path dies |
| SNMP | todo | snmpd integration |
| NetFlow/IPFIX | todo | softflowd or pmacct integration |
| Traffic graphs | todo | Prometheus/node exporter or native counters |
| Scheduler/scripts | todo | systemd timers and hook runner |
| Backup/restore | todo | config export, encrypted secrets backup |
| Multi-user auth/RBAC | todo | users, sessions, MFA/reverse proxy mode |

## Implementation Priorities

1. Add authentication, TLS guidance, audit log, and rollback watchdog before encouraging remote production use.
2. Complete DHCP, VLAN, bridge, dstnat, address-list, and queue renderers; these are core router features.
3. Complete strongSwan, OpenVPN, WireGuard server, PPP/L2TP/SSTP/PPTP, Xray, and sing-box profile renderers.
4. Add FRR for BGP/OSPF/RIP/BFD and VRF-aware routing.
5. Add monitoring dashboards, backup/restore, and safe upgrade workflows.

## References

- RouterOS manual: https://manual.mikrotik.com/
- RouterOS documentation: https://help.mikrotik.com/docs/display/ROS/RouterOS
- MikroTik firewall/QoS manual: https://manual.mikrotik.com/docs/Firewall%20and%20Quality%20of%20Service/
- MikroTik IP routing documentation: https://help.mikrotik.com/docs/spaces/ROS/pages/328084/IP%20Routing
- MikroTik VRF documentation: https://help.mikrotik.com/docs/spaces/ROS/pages/328206/Virtual%20Routing%20and%20Forwarding%20-%20VRF
- MikroTik L2TP documentation: https://help.mikrotik.com/docs/display/ROS/L2TP
- MikroTik IPsec documentation: https://help.mikrotik.com/docs/spaces/ROS/pages/11993097/IPsec
- MikroTik EoIP documentation: https://help.mikrotik.com/docs/spaces/ROS/pages/24805521/EoIP
