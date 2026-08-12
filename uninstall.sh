#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: Run the uninstaller with sudo: sudo ./uninstall.sh [--purge]" >&2
  exit 1
fi

for name in aur-scanner aur-malware-scanner aur-security-auditor; do
  systemctl disable --now "$name.timer" "$name.service" >/dev/null 2>&1 || true
  rm -f "/usr/local/bin/$name" "/usr/local/sbin/$name" "/usr/bin/$name"
  rm -rf "/usr/local/lib/$name" "/usr/lib/$name" "/usr/local/share/$name" "/usr/share/$name"
  rm -f "/usr/local/share/applications/$name.desktop" "/usr/share/applications/$name.desktop"
  rm -f "/usr/share/icons/hicolor/scalable/apps/$name.svg"
  rm -f "/etc/systemd/system/$name.service" "/etc/systemd/system/$name.timer"
  rm -f "/usr/lib/systemd/system/$name.service" "/usr/lib/systemd/system/$name.timer"
done
rm -f /usr/bin/aur-security-auditor-launcher /usr/local/bin/aur-security-auditor-launcher
systemctl daemon-reload >/dev/null 2>&1 || true

if [[ "${1:-}" == "--purge" ]]; then
  target_user="${SUDO_USER:-root}"
  home_dir="$(getent passwd "$target_user" | cut -d: -f6)"
  rm -rf \
    "$home_dir/.config/aur-scanner" "$home_dir/.cache/aur-scanner" "$home_dir/.local/state/aur-scanner" \
    "$home_dir/.config/aur-malware-scanner" "$home_dir/.cache/aur-malware-scanner" "$home_dir/.local/state/aur-malware-scanner" \
    "$home_dir/.config/aur-security-auditor" "$home_dir/.cache/aur-security-auditor" "$home_dir/.local/state/aur-security-auditor"
  echo "AUR Security Auditor and user data have been removed."
else
  echo "AUR Security Auditor has been removed. Reports, suppressions and configuration were preserved."
fi
