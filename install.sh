#!/usr/bin/env bash
set -euo pipefail

ALLOW_FILE_SHARING=0
FORCE_REENROLL=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --allow-file-sharing)
      ALLOW_FILE_SHARING=1
      ;;
    --reenroll)
      FORCE_REENROLL=1
      ;;
    *)
      echo "Usage: sudo bash ./install.sh [--allow-file-sharing] [--reenroll]" >&2
      exit 2
      ;;
  esac
  shift
done

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
  openssh-server \
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

EXISTING_NETWORK_CONFIG="/etc/wireguard/seer0.conf"
EXISTING_INSTALLATION_ID="/var/lib/seer-client/installation-id"
if [[ "$FORCE_REENROLL" -eq 0 &&
      -s "$EXISTING_NETWORK_CONFIG" &&
      -s "$EXISTING_INSTALLATION_ID" &&
      -z "${SEER_INVITATION:-}" ]]; then
  echo "Existing SEER enrollment found. Keeping this device identity."
else
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
fi

systemctl enable --now ssh.service
if ! systemctl is-active --quiet ssh.service; then
  echo "The SSH service could not be started." >&2
  systemctl --no-pager --full status ssh.service >&2 || true
  exit 1
fi

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
  ufw allow from 10.8.0.0/24 to any port 22 proto tcp \
    comment 'SEER approved SSH'
fi

if [[ "$ALLOW_FILE_SHARING" -eq 1 ]] && command -v ufw >/dev/null 2>&1; then
  if ufw status | grep -q '^Status: active'; then
    ufw allow from 10.8.0.0/24 to any port 445 proto tcp \
      comment 'SEER approved file sharing'
  fi
fi

systemctl daemon-reload
systemctl reset-failed seer-client.service 2>/dev/null || true
systemctl enable --now seer-client.service

sleep 3
if ! systemctl is-active --quiet seer-client.service; then
  echo >&2
  echo "SEER was enrolled, but the connection service could not stay running." >&2
  echo "Recent service output:" >&2
  journalctl -u seer-client.service -n 20 --no-pager >&2 || true
  echo >&2
  echo "The installer did not report a successful connection." >&2
  echo "Run 'sudo journalctl -u seer-client -n 100 --no-pager' for details." >&2
  exit 1
fi

echo
echo "SEER is installed and will reconnect automatically after every boot."
private_address="$(/usr/local/bin/seer-client address)"
ssh_user="${SUDO_USER:-YOUR_UBUNTU_USERNAME}"
if [[ -z "$ssh_user" || "$ssh_user" == "root" ]]; then
  ssh_user="YOUR_UBUNTU_USERNAME"
fi
echo "Private address: ${private_address}"
echo "SSH is ready for your existing Ubuntu user on the private address."
echo "Connect with: ssh ${ssh_user}@${private_address}"
echo "Check anytime with: sudo seer-client status"
