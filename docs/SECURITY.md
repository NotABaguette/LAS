# Security

## Operating Assumptions

- Run on a dedicated Debian router host.
- Keep out-of-band access during early configuration.
- Bind the UI to localhost or a trusted management subnet.
- Start without `--apply` while building policies.

## Hardening Checklist

- Put the web UI behind SSH forwarding, a VPN, or a reverse proxy with strong authentication.
- Configure TLS before binding beyond localhost.
- Keep `/etc/debian-router/router.json` mode `0600`; it can contain tunnel config paths and secrets metadata.
- Use least-privilege management CIDRs.
- Keep Suricata, ClamAV signatures, VPN engines, and Debian packages updated.
- Export and review plans before applying changes remotely.

## Known Limits

- The current scaffold does not include a built-in user database or MFA.
- Domain and GeoIP routing need DNS/IP-set generation before strict enforcement.
- Antivirus scanning requires traffic to pass through a proxy/ICAP/file workflow; it cannot decrypt arbitrary TLS.
- OpenVPN, IPsec/L2TP, Xray, and sing-box profiles are referenced but not fully rendered yet.

## Rollback

Keep a local console or SSH session open. Before aggressive firewall changes, save:

```bash
nft list ruleset > /root/ruleset.before
ip route show table all > /root/routes.before
ip rule show > /root/rules.before
```

To recover nftables manually:

```bash
nft flush ruleset
systemctl restart networking
```

