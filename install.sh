#!/usr/bin/env bash
set -euo pipefail

ALLOW_FILE_SHARING=0
if [[ "${1:-}" == "--allow-file-sharing" ]]; then
  ALLOW_FILE_SHARING=1
elif [[ $# -gt 0 ]]; then
  echo "Usage: sudo bash ./install.sh [--allow-file-sharing]" >&2
  exit 2
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this installer with sudo." >&2
  exit 1
fi

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -r "${SCRIPT_DIRECTORY}/release.conf" ||
      ! -r "${SCRIPT_DIRECTORY}/src/seer_client.py" ||
      ! -r "${SCRIPT_DIRECTORY}/systemd/seer-client.service" ]]; then
  echo "The installer files are incomplete. Clone the repository again." >&2
  exit 1
fi

if [[ ! -r /etc/os-release ]]; then
  echo "This installer requires Ubuntu Linux." >&2
  exit 1
fi
# shellcheck disable=SC1091
source /etc/os-release
if [[ "${ID:-}" != "ubuntu" ]]; then
  echo "This installer currently supports Ubuntu Linux only." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates \
  python3 \
  resolvconf \
  wireguard-tools

install -d -m 0700 /etc/seer-client /var/lib/seer-client /etc/wireguard
install -d -m 0755 /usr/local/lib/seer-client
install -m 0600 "${SCRIPT_DIRECTORY}/release.conf" /etc/seer-client/release.conf
install -m 0755 "${SCRIPT_DIRECTORY}/src/seer_client.py" \
  /usr/local/lib/seer-client/seer_client.py
ln -sfn /usr/local/lib/seer-client/seer_client.py /usr/local/bin/seer-client
install -m 0644 "${SCRIPT_DIRECTORY}/systemd/seer-client.service" \
  /etc/systemd/system/seer-client.service

invitation="${SEER_INVITATION:-}"
if [[ -z "$invitation" ]]; then
  read -r -s -p "Paste the invitation from the SEER VPN page: " invitation
  echo
fi
if [[ -z "$invitation" ]]; then
  echo "An invitation is required." >&2
  exit 1
fi

printf '%s\n' "$invitation" \
  | /usr/local/lib/seer-client/seer_client.py enroll --invitation-stdin
unset invitation SEER_INVITATION

if [[ "$ALLOW_FILE_SHARING" -eq 1 ]] && command -v ufw >/dev/null 2>&1; then
  if ufw status | grep -q '^Status: active'; then
    ufw allow from 10.8.0.0/24 to any port 445 proto tcp \
      comment 'SEER approved file sharing'
  fi
fi

systemctl daemon-reload
systemctl enable --now seer-client.service

echo
echo "SEER is installed and will reconnect automatically after every boot."
echo "Private address: $(/usr/local/bin/seer-client address)"
echo "Check anytime with: sudo seer-client status"
