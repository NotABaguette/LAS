#!/usr/bin/env bash
set -euo pipefail

commands=(
  ip
  nft
  wg
  systemctl
  suricata
  clamd
  dnsmasq
)

for cmd in "${commands[@]}"; do
  if command -v "$cmd" >/dev/null 2>&1; then
    printf '%-12s %s\n' "$cmd" "ok"
  else
    printf '%-12s %s\n' "$cmd" "missing"
  fi
done

if [[ -r /proc/sys/net/ipv4/ip_forward ]]; then
  printf '%-12s %s\n' "ip_forward" "$(cat /proc/sys/net/ipv4/ip_forward)"
fi

