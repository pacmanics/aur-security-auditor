#!/usr/bin/env python3
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src/aur-security-auditor"
loader = importlib.machinery.SourceFileLoader("ams_preflight_api_test", str(APP))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)

fixture = {
    "tool": "AUR Security Auditor", "version": module.VERSION, "schema_version": 1,
    "mode": "preflight", "package": "fixture", "input": "fixture",
    "aur_url": "https://aur.archlinux.org/packages/fixture", "started": "2026-08-04T00:00:00+00:00",
    "finished": "2026-08-04T00:00:01+00:00", "risk": "low", "confidence": "medium",
    "confidence_score": 55, "coverage": {"completed": 5, "enabled": 6, "checks": []},
    "recommendation": "Review", "positive_signals": [], "summary": {"findings": 0},
    "findings": [], "provenance": {}, "history": {}, "metadata": {}, "documents": [], "snapshot": {},
    "guard_signature": {"schema_version": 1, "package": "fixture", "version": "1.0-1", "snapshot_sha256": "f" * 64, "documents": {"PKGBUILD": "a" * 64}, "sources": [], "source_hosts": [], "checksum_algorithms": ["sha256"], "skip_count": 0, "functions": ["package"], "install_scripts": [], "surface_files": [], "sensitive_surfaces": [], "maintainer": "tester", "findings": []},
    "safety": {"pkgbuild_executed": False, "shell_used": False, "archive_extracted_to_disk": False},
}
module.preflight_analysis = lambda target, include_history=False: {**fixture, "input": target, "package": module.parse_aur_target(target)}


def call(url, token, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"X-AUR-CSRF": token}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, method=method, data=data, headers=headers)
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read())


with tempfile.TemporaryDirectory(prefix="ams-preflight-api-") as temp:
    os.environ["AUR_SECURITY_AUDITOR_HOME"] = temp
    manager = module.Manager(module.paths())
    token = "test-token"
    nonce = "test-nonce"

    class TestHandler(module.Handler):
        pass

    TestHandler.manager = manager
    TestHandler.token = token
    TestHandler.nonce = nonce
    server = module.http.server.ThreadingHTTPServer(("127.0.0.1", 0), TestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}/"
    try:
        response = call(base + "api/preflight/start", token, "POST", {"target": "fixture", "history": False})
        assert response["ok"] is True, response
        deadline = time.time() + 5
        while time.time() < deadline:
            state = call(base + "api/state", token)
            if state["preflight"]["status"] != "running":
                break
            time.sleep(0.05)
        assert state["preflight"]["status"] == "complete", state["preflight"]
        assert state["preflight"]["report"]["package"] == "fixture"
        report = call(base + "api/preflight/report.json", token)
        assert report["mode"] == "preflight" and report["version"] == module.VERSION, report
        saved = Path(temp) / ".local/state/aur-security-auditor/latest-preflight.json"
        assert saved.is_file()
        approved = call(base + "api/update-guard/approve", token, "POST", {})
        assert approved["ok"] is True and approved["approval"]["package"] == "fixture", approved
        state = call(base + "api/state", token)
        assert state["preflight"]["report"]["update_guard"]["exact_match"] is True, state["preflight"]["report"]["update_guard"]
        approvals = call(base + "api/update-guard/approvals", token)
        assert len(approvals["approvals"]) == 1, approvals
        removed = call(base + "api/update-guard/remove", token, "POST", {"package": "fixture"})
        assert removed["removed"] is True, removed
        cleared = call(base + "api/preflight/clear", token, "POST", {})
        assert cleared["ok"] is True, cleared
        state = call(base + "api/state", token)
        assert state["preflight"]["status"] == "idle", state["preflight"]
        assert not saved.exists()
    finally:
        server.shutdown()
        server.server_close()

print("Preflight API integration test: OK")
print("  ✓ asynchronous start endpoint")
print("  ✓ state polling and completed report")
print("  ✓ dedicated JSON endpoint")
print("  ✓ local report persistence")
print("  ✓ Update Guard approval, listing and removal endpoints")
print("  ✓ neutral removal endpoint clears only the saved Preflight result")
