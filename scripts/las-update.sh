#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

if [[ -f /etc/default/las-updater ]]; then
  # shellcheck disable=SC1091
  source /etc/default/las-updater
fi

LAS_APT_UPDATE="${LAS_APT_UPDATE:-1}"
LAS_APT_UPGRADE="${LAS_APT_UPGRADE:-1}"
LAS_FRESHCLAM="${LAS_FRESHCLAM:-1}"
LAS_UPDATE_CORES="${LAS_UPDATE_CORES:-1}"
LAS_CORE_ARGS="${LAS_CORE_ARGS:-}"

if [[ "$LAS_APT_UPDATE" == "1" ]] && command -v apt-get >/dev/null 2>&1; then
  apt-get update
fi

if [[ "$LAS_APT_UPGRADE" == "1" ]] && command -v apt-get >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get -y upgrade
fi

if [[ "$LAS_FRESHCLAM" == "1" ]] && command -v freshclam >/dev/null 2>&1; then
  freshclam || true
fi

if [[ "$LAS_UPDATE_CORES" == "1" ]]; then
  /usr/local/sbin/las-update-cores $LAS_CORE_ARGS
fi

