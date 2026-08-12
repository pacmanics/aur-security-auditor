#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

python -m py_compile src/aur-security-auditor src/core.py
src/aur-security-auditor --self-test
bash -n install.sh uninstall.sh src/aur-security-auditor-launcher

python - <<'PY'
from pathlib import Path
import re
for rel in ['src/aur-security-auditor', 'src/core.py']:
    text = Path(rel).read_text()
    assert 'VERSION = "1.4.8"' in text, rel
launcher = Path('src/aur-security-auditor-launcher').read_text()
assert 'VERSION=1.4.8' in launcher
installer = Path('install.sh').read_text()
assert 'VERSION="1.4.8"' in installer
html = Path('data/dashboard.html').read_text()
for token in [
    '__TOKEN__', '__NONCE__', 'const TOKEN="__TOKEN__"', '/api/scan/start',
    '/api/package/uninstall', '/api/dependencies', 'id="phaseTrack"', 'id="eta"',
    'id="languageSelect"', 'English', 'Deutsch', 'NO SCAN DATA',
    'localStorage.getItem(STORAGE_KEY)', 'aur-security-auditor-language',
    'id="logLatestBtn"', 'ROOT ACCESS', 'ROOT-ZUGRIFF', 'AUR package page',
    'Upstream project', 'target="_blank"', 'rel="noopener noreferrer"', '/icon.svg',
    'id="optHistory"', 'id="evidenceBtn"', 'id="deltaStatus"', '/api/evidence.zip',
    'id="preflightTarget"', 'id="preflightBtn"', 'id="preflightRemove"', '/api/preflight/start', '/api/preflight/clear',
    'id="deepBtn"', 'id="deepResult"', '/api/deep/start', '/api/deep/evidence.zip',
    'id="navHelp"', '© PacmanicS', 'v__VERSION__',
    'id="guardResult"', 'id="guardApprove"', 'id="guardModal"', '/api/update-guard/approve', '/api/update-guard/remove'
]:
    assert token in html, token
assert 'Dashboard geöffnet. Noch kein Scan gestartet.' not in html
assert 'Dashboard bereit. Noch kein Scan gestartet.' not in html
assert 'BIND 127.0.0.1' not in html and 'DYNAMIC PORT' not in html and 'EXTERNAL ASSETS 0' not in html
assert 'grid-template-columns:78px minmax(138px,160px)' in html
assert '.setting-title{display:block' in html and '.setting-desc{display:block' in html
assert 'position:fixed;top:0;left:0;right:0' in html
assert 'logFollowing' in html and 'scrollHeight-log.scrollTop-log.clientHeight' in html
source = Path('src/aur-security-auditor').read_text()
main = source[source.index('def main():'):]
assert 'if args.auto_scan:' in main
assert '"status": "idle", "phase": "READY", "detail": "NO SCAN DATA"' in source
assert 'shell=True' not in source and 'shell=True' not in Path('src/core.py').read_text()
assert '/api/preflight/report.json' in source
assert 're.split(r"[<>=]", item, maxsplit=1)' in source
assert 're.split(r"[<>=]", item, 1)' not in source
legacy_display = 'AUR ' + 'Malware Scanner'
assert legacy_display not in source
assert legacy_display not in html
assert 'id="deepCancel"' in html and '/api/deep/cancel' in source
assert 'id="appDialogOverlay"' in html
print('Release consistency test: OK')
PY

# Exercise dependency parsing with deprecations promoted to errors.
python -W error::DeprecationWarning - <<'PY'
import importlib.machinery
import importlib.util
from pathlib import Path
from types import SimpleNamespace

path = Path('src/aur-security-auditor').resolve()
loader = importlib.machinery.SourceFileLoader('ams_launcher_warning_test', str(path))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
module.core.run = lambda *args, **kwargs: SimpleNamespace(
    returncode=0,
    stderr='',
    stdout=(
        'Name            : test-package\n'
        'Version         : 1.2.3-1\n'
        'Description     : test\n'
        'URL             : https://example.invalid\n'
        'Depends On      : python>=3.12 glibc<3\n'
        'Required By     : app=1.0\n'
        'Optional For    : None\n'
    ),
)
metadata = module.package_metadata('test-package')
assert metadata['depends'] == ['python', 'glibc'], metadata
assert metadata['required_by'] == ['app'], metadata
print('DeprecationWarning regression test: OK')
PY

python - <<'PY'
from pathlib import Path
html = Path('data/dashboard.html').read_text()
script = html.split('<script nonce="__NONCE__">', 1)[1].split('</script>', 1)[0]
Path('/tmp/aur-security-auditor-dashboard.js').write_text(script)
PY
node --check /tmp/aur-security-auditor-dashboard.js
python tests/security-features.py
python tests/preflight-security.py
python tests/preflight-api.py
python tests/deep-security.py
python tests/update-guard.py
python tests/i18n-audit.py
python tests/release-polish-144.py
python tests/context-awareness-145.py
python tests/false-positive-regression-148.py
python tests/startup-launcher-147.py
python tests/hardening.py
python tests/http-hardening.py

# Test installer in an isolated fake root, including legacy data migration.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p \
  "$tmp/root/usr/local/bin" \
  "$tmp/root/usr/local/lib/aur-scanner" \
  "$tmp/downloads/aur-scanner-0.0.1/aur-scanner-report" \
  "$tmp/home/.config/aur-scanner" \
  "$tmp/home/.local/state/aur-scanner/reports" \
  "$tmp/home/.config/aur-malware-scanner" \
  "$tmp/home/.local/state/aur-malware-scanner/reports"
printf old > "$tmp/root/usr/local/bin/aur-scanner"
printf old > "$tmp/root/usr/local/lib/aur-scanner/core.py"
printf '{"legacy":true}\n' > "$tmp/home/.config/aur-scanner/suppressions.json"
printf report > "$tmp/home/.local/state/aur-scanner/reports/legacy-report.json"
printf legacy-malware > "$tmp/home/.config/aur-malware-scanner/update-guard.json"
printf legacy-malware-report > "$tmp/home/.local/state/aur-malware-scanner/reports/malware-era-report.json"
printf old > "$tmp/downloads/aur-scanner-dashboard-0.0.1.tar.gz"
printf current > "$tmp/downloads/aur-security-auditor-1.4.8.tar.gz"
printf current > "$tmp/downloads/aur-security-auditor-1.4.8.sha256"
AUR_SECURITY_AUDITOR_ROOT="$tmp/root" \
AUR_SECURITY_AUDITOR_DOWNLOAD_DIR="$tmp/downloads" \
AUR_SECURITY_AUDITOR_TEST_CLEAN_DOWNLOADS=1 \
AUR_SECURITY_AUDITOR_TEST_MIGRATION=1 \
HOME="$tmp/home" USER=root \
./install.sh >/tmp/aur-security-auditor-install-test.log
[[ -x "$tmp/root/usr/bin/aur-security-auditor" ]]
[[ -x "$tmp/root/usr/bin/aur-security-auditor-launcher" ]]
[[ -f "$tmp/root/usr/lib/aur-security-auditor/core.py" ]]
[[ -f "$tmp/root/usr/share/aur-security-auditor/dashboard.html" ]]
[[ -f "$tmp/root/usr/share/aur-security-auditor/aur-security-auditor.svg" ]]
[[ -f "$tmp/root/usr/share/icons/hicolor/scalable/apps/aur-security-auditor.svg" ]]
[[ ! -e "$tmp/root/usr/local/bin/aur-scanner" ]]
[[ ! -e "$tmp/root/usr/local/lib/aur-scanner" ]]
[[ ! -e "$tmp/downloads/aur-scanner-dashboard-0.0.1.tar.gz" ]]
[[ ! -e "$tmp/downloads/aur-scanner-0.0.1" ]]
[[ -e "$tmp/downloads/aur-security-auditor-1.4.8.tar.gz" ]]
[[ -e "$tmp/downloads/aur-security-auditor-1.4.8.sha256" ]]
[[ -f "$tmp/home/.config/aur-security-auditor/suppressions.json" ]]
[[ -f "$tmp/home/.local/state/aur-security-auditor/reports/legacy-report.json" ]]
[[ -f "$tmp/home/.config/aur-security-auditor/update-guard.json" ]]
[[ -f "$tmp/home/.local/state/aur-security-auditor/reports/malware-era-report.json" ]]
[[ "$(stat -c %a "$tmp/home/.config/aur-security-auditor")" == "700" ]]
[[ "$(stat -c %a "$tmp/home/.cache/aur-security-auditor")" == "700" ]]
[[ "$(stat -c %a "$tmp/home/.local/state/aur-security-auditor")" == "700" ]]
[[ "$(stat -c %a "$tmp/home/.config/aur-security-auditor/suppressions.json")" == "600" ]]
[[ "$(stat -c %a "$tmp/home/.local/state/aur-security-auditor/reports/legacy-report.json")" == "600" ]]
[[ ! -e "$tmp/home/.config/aur-scanner" ]]
[[ ! -e "$tmp/home/.config/aur-malware-scanner" ]]
grep -q 'VERSION = "1.4.8"' "$tmp/root/usr/bin/aur-security-auditor"

# The privileged installer must not follow user-controlled scanner data symlinks.
mkdir -p "$tmp/symlink-home/.config" "$tmp/symlink-target" "$tmp/symlink-root"
chmod 755 "$tmp/symlink-target"
ln -s "$tmp/symlink-target" "$tmp/symlink-home/.config/aur-security-auditor"
if AUR_SECURITY_AUDITOR_ROOT="$tmp/symlink-root" \
   AUR_SECURITY_AUDITOR_TEST_MIGRATION=1 \
   HOME="$tmp/symlink-home" USER=root \
   ./install.sh >/tmp/aur-security-auditor-symlink-install.log 2>&1; then
  echo "Installer accepted a symlinked private data directory" >&2
  exit 1
fi
[[ "$(stat -c %a "$tmp/symlink-target")" == "755" ]]

python3 tests/runtime-network-context-148.py
python3 tests/generic-rule-corpus-148.py
python tests/integration-dashboard.py
echo 'Static, installer and integration tests: OK'
