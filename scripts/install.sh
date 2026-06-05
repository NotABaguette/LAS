#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

if ! command -v go >/dev/null 2>&1; then
  echo "Go is required to build lasd. Install golang-go first." >&2
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
  frr \
  suricata \
  clamav-daemon \
  clamav-freshclam \
  dnsmasq \
  chrony \
  traceroute \
  dnsutils \
  iputils-ping \
  unattended-upgrades \
  python3 \
  unzip \
  curl \
  ca-certificates

go build -o lasd ./cmd/lasd

install -d /etc/las
install -d /etc/default
install -d /etc/las/wireguard
install -d /etc/las/xray
install -d /etc/las/sing-box
install -d /var/lib/las
install -d /usr/share/las/web
install -m 0755 lasd /usr/local/sbin/lasd
install -m 0755 scripts/update-cores.py /usr/local/sbin/las-update-cores
install -m 0755 scripts/las-update.sh /usr/local/sbin/las-update
cp -R web/. /usr/share/las/web/
install -m 0644 README.md /usr/share/las/README.md

if [[ ! -f /etc/las/router.json ]]; then
  install -m 0600 configs/router.example.json /etc/las/router.json
fi
if [[ ! -f /etc/default/las-updater ]]; then
  install -m 0644 configs/las-updater.env /etc/default/las-updater
fi

install -m 0644 systemd/lasd.service /etc/systemd/system/lasd.service
install -m 0644 systemd/las-updater.service /etc/systemd/system/las-updater.service
install -m 0644 systemd/las-updater.timer /etc/systemd/system/las-updater.timer
systemctl daemon-reload
systemctl enable --now las-updater.timer

echo "Installed lasd."
echo "Edit /etc/las/router.json, then run: systemctl enable --now lasd"
echo "Periodic updates are controlled by /etc/default/las-updater and las-updater.timer"
