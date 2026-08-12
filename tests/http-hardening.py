#!/usr/bin/env python3
from __future__ import annotations

import http.client
import os
import re
import signal
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src/aur-security-auditor"


def response(port: int, method: str, path: str, *, headers=None, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    conn.request(method, path, body=body, headers=headers or {})
    res = conn.getresponse()
    payload = res.read()
    result = (res.status, dict(res.getheaders()), payload)
    conn.close()
    return result


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ams-http-hardening-") as temp:
        base = Path(temp)
        fake_bin = base / "bin"
        fake_bin.mkdir()
        pacman = fake_bin / "pacman"
        pacman.write_text("#!/usr/bin/env bash\nexit 0\n")
        pacman.chmod(0o755)
        home = base / "home"
        home.mkdir()
        env = os.environ.copy()
        env["PATH"] = str(fake_bin) + os.pathsep + env["PATH"]
        env["HOME"] = str(home)
        env["AUR_SECURITY_AUDITOR_HOME"] = str(home)
        env["PYTHONUNBUFFERED"] = "1"
        proc = subprocess.Popen(
            [str(APP), "--no-browser"], cwd=ROOT, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        try:
            deadline = time.time() + 10
            port = None
            output = []
            while time.time() < deadline:
                line = proc.stdout.readline()
                if line:
                    output.append(line)
                    match = re.search(r"Dashboard: http://127\.0\.0\.1:(\d+)/", line)
                    if match:
                        port = int(match.group(1))
                        break
                elif proc.poll() is not None:
                    raise RuntimeError("Dashboard terminated early: " + "".join(output))
            assert port is not None
            host = f"127.0.0.1:{port}"

            status, _, _ = response(port, "GET", "/", headers={"Host": "scanner.attacker.invalid"})
            assert status == 403, status

            status, headers, page = response(port, "GET", "/", headers={"Host": host})
            assert status == 200, status
            page_text = page.decode()
            token_match = re.search(r'const TOKEN="([^"]+)"', page_text)
            assert token_match
            token = token_match.group(1)
            assert headers.get("Cross-Origin-Opener-Policy") == "same-origin"
            assert headers.get("Cross-Origin-Resource-Policy") == "same-origin"
            assert "base-uri 'none'" in headers.get("Content-Security-Policy", "")
            assert "form-action 'none'" in headers.get("Content-Security-Policy", "")

            common = {"Host": host, "X-AUR-CSRF": token, "Content-Type": "application/json"}
            status, _, _ = response(
                port, "POST", "/api/scan/start",
                headers={**common, "Origin": "http://scanner.attacker.invalid"}, body=b"{}",
            )
            assert status == 403, status

            status, _, _ = response(
                port, "POST", "/api/scan/start",
                headers={"Host": host, "X-AUR-CSRF": token, "Content-Type": "text/plain"}, body=b"{}",
            )
            assert status == 415, status

            status, _, _ = response(
                port, "POST", "/api/scan/start", headers=common, body=b"[]",
            )
            assert status == 400, status
        finally:
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)

    print("Dashboard HTTP hardening test: OK")
    print("  ✓ forged Host headers blocked")
    print("  ✓ cross-origin POST requests blocked")
    print("  ✓ strict JSON media type and object validation")
    print("  ✓ hardened browser security headers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
