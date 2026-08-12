#!/usr/bin/env bash
set -euo pipefail

VERSION="1.4.8"
ROOT_PREFIX="${AUR_SECURITY_AUDITOR_ROOT:-${AUR_MALWARE_SCANNER_ROOT:-${AUR_SCANNER_ROOT:-}}}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

if [[ -z "$ROOT_PREFIX" && $EUID -ne 0 ]]; then
  echo "ERROR: Run the installer with sudo: sudo ./install.sh" >&2
  exit 1
fi

invoking_user="${SUDO_USER:-${USER:-root}}"
if [[ "$invoking_user" != "root" ]] && command -v getent >/dev/null 2>&1; then
  user_home="$(getent passwd "$invoking_user" | cut -d: -f6)"
else
  user_home="${HOME:-/root}"
fi
download_dir="${AUR_SECURITY_AUDITOR_DOWNLOAD_DIR:-${AUR_MALWARE_SCANNER_DOWNLOAD_DIR:-${AUR_SCANNER_DOWNLOAD_DIR:-$user_home/Downloads}}}"

root_path() { printf '%s%s' "$ROOT_PREFIX" "$1"; }
remove_path() {
  local target
  target="$(root_path "$1")"
  if [[ -e "$target" || -L "$target" ]]; then
    rm -rf -- "$target"
  fi
}

migrate_tree() {
  local old_path="$1" new_path="$2"
  [[ -L "$old_path" ]] && { echo "ERROR: Unsafe symlinked data path: $old_path" >&2; exit 1; }
  [[ -L "$new_path" ]] && { echo "ERROR: Unsafe symlinked data path: $new_path" >&2; exit 1; }
  [[ -d "$old_path" ]] || return 0
  mkdir -p -- "$(dirname -- "$new_path")"
  if [[ ! -e "$new_path" ]]; then
    mv -- "$old_path" "$new_path"
  else
    cp -a -n -- "$old_path"/. "$new_path"/ 2>/dev/null || true
    rm -rf -- "$old_path"
  fi
}

printf 'AUR Security Auditor %s · clean local installation\n' "$VERSION"
printf '%s\n' '--------------------------------------------------------'

# Stop stale services from both the historical and final identities.
if [[ -z "$ROOT_PREFIX" ]] && command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now \
    aur-scanner.timer aur-scanner.service \
    aur-malware-scanner.timer aur-malware-scanner.service \
    aur-security-auditor.timer aur-security-auditor.service \
    >/dev/null 2>&1 || true
fi

# Remove an old package-managed predecessor before installing the standalone build.
if [[ -z "$ROOT_PREFIX" ]] && command -v pacman >/dev/null 2>&1; then
  for package in aur-scanner aur-malware-scanner aur-security-auditor; do
    if pacman -Q "$package" >/dev/null 2>&1; then
      pacman -R --noconfirm "$package"
    fi
  done
fi

# Remove all known historical installation locations.
for name in aur-scanner aur-malware-scanner aur-security-auditor; do
  for path in \
    "/usr/local/bin/$name" "/usr/local/sbin/$name" "/usr/bin/$name" \
    "/usr/local/lib/$name" "/usr/lib/$name" \
    "/usr/local/share/$name" "/usr/share/$name" \
    "/usr/local/share/applications/$name.desktop" "/usr/share/applications/$name.desktop" \
    "/etc/systemd/system/$name.service" "/etc/systemd/system/$name.timer" \
    "/usr/lib/systemd/system/$name.service" "/usr/lib/systemd/system/$name.timer"; do
    remove_path "$path"
  done
done

remove_path "/usr/bin/aur-security-auditor-launcher"
remove_path "/usr/local/bin/aur-security-auditor-launcher"

# Preserve and migrate old reports, suppressions, cache and configuration.
if [[ -z "$ROOT_PREFIX" || "${AUR_SECURITY_AUDITOR_TEST_MIGRATION:-0}" == "1" ]]; then
  migrate_tree "$user_home/.config/aur-scanner" "$user_home/.config/aur-security-auditor"
  migrate_tree "$user_home/.cache/aur-scanner" "$user_home/.cache/aur-security-auditor"
  migrate_tree "$user_home/.local/state/aur-scanner" "$user_home/.local/state/aur-security-auditor"
  migrate_tree "$user_home/.config/aur-malware-scanner" "$user_home/.config/aur-security-auditor"
  migrate_tree "$user_home/.cache/aur-malware-scanner" "$user_home/.cache/aur-security-auditor"
  migrate_tree "$user_home/.local/state/aur-malware-scanner" "$user_home/.local/state/aur-security-auditor"
  for private_path in \
    "$user_home/.config/aur-security-auditor" \
    "$user_home/.cache/aur-security-auditor" \
    "$user_home/.local/state/aur-security-auditor" \
    "$user_home/.local/state/aur-security-auditor/reports"; do
    if [[ -L "$private_path" ]]; then
      echo "ERROR: Unsafe symlinked data path: $private_path" >&2
      exit 1
    fi
  done
  mkdir -p \
    "$user_home/.config/aur-security-auditor" \
    "$user_home/.cache/aur-security-auditor" \
    "$user_home/.local/state/aur-security-auditor/reports"
  chmod 700 \
    "$user_home/.config/aur-security-auditor" \
    "$user_home/.cache/aur-security-auditor" \
    "$user_home/.local/state/aur-security-auditor" \
    "$user_home/.local/state/aur-security-auditor/reports" 2>/dev/null || true
  find \
    "$user_home/.config/aur-security-auditor" \
    "$user_home/.local/state/aur-security-auditor" \
    -type f -exec chmod 600 {} + 2>/dev/null || true
  if [[ -z "$ROOT_PREFIX" && "$invoking_user" != "root" ]]; then
    chown -R "$invoking_user":"$(id -gn "$invoking_user")" \
      "$user_home/.config/aur-security-auditor" \
      "$user_home/.cache/aur-security-auditor" \
      "$user_home/.local/state/aur-security-auditor"
  fi
fi

install -Dm755 "$SCRIPT_DIR/src/aur-security-auditor" "$(root_path /usr/bin/aur-security-auditor)"
install -Dm755 "$SCRIPT_DIR/src/aur-security-auditor-launcher" "$(root_path /usr/bin/aur-security-auditor-launcher)"
install -Dm644 "$SCRIPT_DIR/src/core.py" "$(root_path /usr/lib/aur-security-auditor/core.py)"
install -Dm644 "$SCRIPT_DIR/data/dashboard.html" "$(root_path /usr/share/aur-security-auditor/dashboard.html)"
install -Dm644 "$SCRIPT_DIR/data/atomic-arch-packages.txt" "$(root_path /usr/share/aur-security-auditor/atomic-arch-packages.txt)"
install -Dm644 "$SCRIPT_DIR/data/iocs.json" "$(root_path /usr/share/aur-security-auditor/iocs.json)"
install -Dm644 "$SCRIPT_DIR/data/aur-security-auditor.svg" "$(root_path /usr/share/aur-security-auditor/aur-security-auditor.svg)"
install -Dm644 "$SCRIPT_DIR/data/aur-security-auditor.svg" "$(root_path /usr/share/icons/hicolor/scalable/apps/aur-security-auditor.svg)"
install -Dm644 "$SCRIPT_DIR/aur-security-auditor.desktop" "$(root_path /usr/share/applications/aur-security-auditor.desktop)"

if [[ -z "$ROOT_PREFIX" ]] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
if [[ -z "$ROOT_PREFIX" ]] && command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
fi

# Clean old scanner release archives and extracted version folders in Downloads.
removed_downloads=0
if [[ ( -z "$ROOT_PREFIX" || "${AUR_SECURITY_AUDITOR_TEST_CLEAN_DOWNLOADS:-${AUR_SCANNER_TEST_CLEAN_DOWNLOADS:-0}}" == "1" ) && -d "$download_dir" ]]; then
  shopt -s nullglob
  for item in \
    "$download_dir"/aur-scanner-dashboard-*.tar.gz \
    "$download_dir"/aur-scanner-dashboard-*.sha256 \
    "$download_dir"/aur-scanner-[0-9]*.tar.gz \
    "$download_dir"/aur-scanner-[0-9]*.sha256 \
    "$download_dir"/aur-scanner-[0-9]*.py \
    "$download_dir"/aur-malware-scanner-dashboard-*.tar.gz \
    "$download_dir"/aur-malware-scanner-dashboard-*.sha256 \
    "$download_dir"/aur-malware-scanner-[0-9]*.tar.gz \
    "$download_dir"/aur-malware-scanner-[0-9]*.sha256 \
    "$download_dir"/aur-malware-scanner-[0-9]*.py \
    "$download_dir"/aur-security-auditor-dashboard-*.tar.gz \
    "$download_dir"/aur-security-auditor-dashboard-*.sha256 \
    "$download_dir"/aur-security-auditor-[0-9]*.tar.gz \
    "$download_dir"/aur-security-auditor-[0-9]*.sha256 \
    "$download_dir"/aur-security-auditor-[0-9]*.py; do
    base="$(basename -- "$item")"
    case "$base" in
      "aur-security-auditor-$VERSION.tar.gz"|"aur-security-auditor-$VERSION.sha256") continue ;;
    esac
    rm -f -- "$item" && ((removed_downloads+=1)) || true
  done
  for item in \
    "$download_dir"/aur-scanner-[0-9]* "$download_dir"/aur-scanner-v* \
    "$download_dir"/aur-malware-scanner-[0-9]* "$download_dir"/aur-malware-scanner-v* \
    "$download_dir"/aur-security-auditor-[0-9]* "$download_dir"/aur-security-auditor-v*; do
    [[ -d "$item" ]] || continue
    item_real="$(cd -- "$item" 2>/dev/null && pwd -P || true)"
    [[ -n "$item_real" && "$item_real" == "$SCRIPT_DIR" ]] && continue
    rm -rf -- "$item" && ((removed_downloads+=1)) || true
  done
  shopt -u nullglob
fi

if [[ -n "$ROOT_PREFIX" ]]; then
  installed_version="$(grep -m1 -oE 'VERSION = "[^"]+"' "$(root_path /usr/bin/aur-security-auditor)" | cut -d'"' -f2)"
else
  installed_version="$("$(root_path /usr/bin/aur-security-auditor)" --version 2>/dev/null || true)"
fi
if [[ "$installed_version" != "$VERSION" ]]; then
  echo "ERROR: Installed version is '$installed_version', expected '$VERSION'." >&2
  exit 1
fi

printf '\nInstallation verified: /usr/bin/aur-security-auditor %s\n' "$installed_version"
printf 'Bereinigte alte Download-Artefakte: %d\n' "$removed_downloads"
printf '\nStart via application menu or CLI:\n  aur-security-auditor-launcher\n  sudo aur-security-auditor\n\n'
printf '%s\n' 'Das Dashboard öffnet lokal und startet keinen Scan automatisch.'
printf '%s\n' 'Reports, suppressions and configuration were preserved and migrated.'
