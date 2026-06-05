#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

if ! command -v go >/dev/null 2>&1; then
  echo "Go is required to build debian-routerd. Install golang-go first." >&2
  exit 1
fi

apt-get update
apt-get install -y \
  nftables \
  iproute2 \
  iptables \
  wireguard-tools \
  openvpn \
  strongswan \
  xl2tpd \
  suricata \
  clamav-daemon \
  clamav-freshclam \
  dnsmasq \
  curl \
  ca-certificates

go build -o debian-routerd ./cmd/debian-routerd

install -d /etc/debian-router
install -d /etc/debian-router/wireguard
install -d /etc/debian-router/xray
install -d /var/lib/debian-router
install -d /usr/share/debian-router/web
install -m 0755 debian-routerd /usr/local/sbin/debian-routerd
cp -R web/. /usr/share/debian-router/web/

if [[ ! -f /etc/debian-router/router.json ]]; then
  install -m 0600 configs/router.example.json /etc/debian-router/router.json
fi

install -m 0644 systemd/debian-routerd.service /etc/systemd/system/debian-routerd.service
systemctl daemon-reload

echo "Installed debian-routerd."
echo "Edit /etc/debian-router/router.json, then run: systemctl enable --now debian-routerd"

